// Copyright (C) 2016-2021 Thomas Fussell
// Copyright (C) 2002-2007 Ariya Hidayat (ariya@kde.org).
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
//
// 1. Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright
// notice, this list of conditions and the following disclaimer in the
// documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
// OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
// IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
// INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
// NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
// THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include <algorithm>
#include <array>
#include <assert.h>
#include <cstring>
#include <iostream>
#include <locale>
#include <string>
#include <vector>
#include <list>

#include <xlnt/utils/exceptions.hpp>
#include <detail/binary.hpp>
#include <detail/cryptography/compound_document.hpp>
#include <detail/unicode.hpp>

namespace {

using namespace xlnt::detail;

int compare_keys(const std::string &left, const std::string &right)
{
    auto to_lower = [](std::string s) {
        static const auto locale = std::locale();
        std::use_facet<std::ctype<char>>(locale).tolower(&s[0], &s[0] + s.size());

        return s;
    };
    if (left.size() != right.size())
        return left.size() - right.size();
    else
        return to_lower(left).compare(to_lower(right));
}

std::vector<std::string> split_path(const std::string &path)
{
    auto split = std::vector<std::string>();
    auto prev = std::size_t(1);
    auto current = path.find('/', prev);

    while (current != std::string::npos)
    {
        split.push_back(path.substr(prev, current - prev));
        prev = current + 1;
        current = path.find('/', prev);
    }

    split.push_back(path.substr(prev));

    return split;
}

template <typename T>
std::string join_path(const T &path)
{
    auto joined = std::string();

    for (auto part : path)
    {
        joined.push_back('/');
        joined.append(part);
    }

    return joined;
}

} // namespace

namespace xlnt {
namespace detail {

/// <summary>
/// Allows a std::vector to be read through a std::istream.
/// </summary>
class compound_document_istreambuf : public std::streambuf
{
    using int_type = std::streambuf::int_type;

public:
    compound_document_istreambuf(const compound_document_entry &entry, compound_document &document)
        : entry_(entry),
          document_(document),
          sector_writer_(current_sector_),
          position_(0)
    {
    }

    compound_document_istreambuf(const compound_document_istreambuf &) = delete;
    compound_document_istreambuf &operator=(const compound_document_istreambuf &) = delete;

    ~compound_document_istreambuf() override;

private:
    std::streamsize xsgetn(char *c, std::streamsize count) override
    {
        auto bytes_read = std::streamsize(0);

        const auto sector_chain = short_stream() ? document_.ssat_ : document_.sat_;
        const auto chain = document_.follow_chain(entry_.start, sector_chain);
        const auto sector_size = short_stream() ? document_.short_sector_size() : document_.sector_size();
        auto current_sector = chain[position_ / sector_size];
        auto remaining = std::min(std::size_t(entry_.size) - position_, std::size_t(count));

        while (remaining)
        {
            if (current_sector_.empty() || chain[position_ / sector_size] != current_sector)
            {
                current_sector = chain[position_ / sector_size];
                sector_writer_.reset();
                if (short_stream())
                {
                    document_.read_short_sector(current_sector, sector_writer_);
                }
                else
                {
                    document_.read_sector(current_sector, sector_writer_);
                }
            }

            const auto available = std::min(entry_.size - position_,
                sector_size - position_ % sector_size);
            const auto to_read = std::min(available, std::size_t(remaining));

            auto start = current_sector_.begin() + static_cast<std::ptrdiff_t>(position_ % sector_size);
            auto end = start + static_cast<std::ptrdiff_t>(to_read);

            for (auto i = start; i < end; ++i)
            {
                *(c++) = static_cast<char>(*i);
            }

            remaining -= to_read;
            position_ += to_read;
            bytes_read += to_read;
        }

        if (position_ < entry_.size && chain[position_ / sector_size] != current_sector)
        {
            current_sector = chain[position_ / sector_size];
            sector_writer_.reset();
            if (short_stream())
            {
                document_.read_short_sector(current_sector, sector_writer_);
            }
            else
            {
                document_.read_sector(current_sector, sector_writer_);
            }
        }

        return bytes_read;
    }

    bool short_stream()
    {
        return entry_.size < document_.header_.threshold;
    }

    int_type underflow() override
    {
        if (position_ >= entry_.size)
        {
            return traits_type::eof();
        }

        auto old_position = position_;
        auto result = '\0';
        xsgetn(&result, 1);
        position_ = old_position;

        return result;
    }

    int_type uflow() override
    {
        auto result = underflow();
        ++position_;

        return result;
    }

    std::streamsize showmanyc() override
    {
        if (position_ == entry_.size)
        {
            return static_cast<std::streamsize>(-1);
        }

        return static_cast<std::streamsize>(entry_.size - position_);
    }

    std::streampos seekoff(std::streamoff off, std::ios_base::seekdir way, std::ios_base::openmode) override
    {
        if (way == std::ios_base::beg)
        {
            position_ = 0;
        }
        else if (way == std::ios_base::end)
        {
            position_ = entry_.size;
        }

        if (off < 0)
        {
            if (static_cast<std::size_t>(-off) > position_)
            {
                position_ = 0;
                return static_cast<std::ptrdiff_t>(-1);
            }
            else
            {
                position_ -= static_cast<std::size_t>(-off);
            }
        }
        else if (off > 0)
        {
            if (static_cast<std::size_t>(off) + position_ > entry_.size)
            {
                position_ = entry_.size;
                return static_cast<std::ptrdiff_t>(-1);
            }
            else
            {
                position_ += static_cast<std::size_t>(off);
            }
        }

        return static_cast<std::ptrdiff_t>(position_);
    }

    std::streampos seekpos(std::streampos sp, std::ios_base::openmode) override
    {
        if (sp < 0)
        {
            position_ = 0;
        }
        else if (static_cast<std::size_t>(sp) > entry_.size)
        {
            position_ = entry_.size;
        }
        else
        {
            position_ = static_cast<std::size_t>(sp);
        }

        return static_cast<std::ptrdiff_t>(position_);
    }

private:
    const compound_document_entry &entry_;
    compound_document &document_;
    binary_writer<byte> sector_writer_;
    std::vector<byte> current_sector_;
    std::size_t position_;
};

compound_document_istreambuf::~compound_document_istreambuf()
{
}

/// <summary>
/// Allows a std::vector to be written through a std::ostream.
/// </summary>
class compound_document_ostreambuf : public std::streambuf
{
    using int_type = std::streambuf::int_type;
    using change_bit = compound_document::change_bit;

public:
    compound_document_ostreambuf(compound_document_entry &entry, compound_document &document)
        : entry_(entry),
          document_(document),
          sector_reader_(current_sector_),
          current_sector_(document.header_.threshold),
          position_(0)
    {
        setp(reinterpret_cast<char *>(current_sector_.data()),
            reinterpret_cast<char *>(current_sector_.data() + current_sector_.size()));
    }

    compound_document_ostreambuf(const compound_document_ostreambuf &) = delete;
    compound_document_ostreambuf &operator=(const compound_document_ostreambuf &) = delete;

    ~compound_document_ostreambuf() override;

private:
    int sync() override
    {
        auto written = static_cast<std::size_t>(pptr() - pbase());

        if (written == std::size_t(0))
        {
            return 0;
        }

        sector_reader_.reset();

        if (short_stream())
        {
            if (position_ + written >= document_.header_.threshold)
            {
                convert_to_long_stream();
            }
            else
            {
                if (entry_.start <= 0)
                {
                    auto num_sectors = (position_ + written + document_.short_sector_size() - 1) / document_.short_sector_size();
                    chain_ = document_.allocate_short_sectors(num_sectors);
                    entry_.start = chain_.front();
                }

                for (auto link : chain_)
                {
                    document_.write_short_sector(sector_reader_, link);
                    sector_reader_.offset(sector_reader_.offset() + document_.short_sector_size());
                }
            }
        }
        else
        {
            const auto sector_index = position_ / document_.sector_size();
            document_.write_sector(sector_reader_, chain_[sector_index]);
        }

        position_ += written;
        entry_.size = std::max(entry_.size, static_cast<std::uint32_t>(position_));
        document_.change_ |= change_bit::dir_bit;

        std::fill(current_sector_.begin(), current_sector_.end(), byte(0));
        setp(reinterpret_cast<char *>(current_sector_.data()),
            reinterpret_cast<char *>(current_sector_.data() + current_sector_.size()));

        return 0;
    }

    bool short_stream()
    {
        return entry_.size < document_.header_.threshold;
    }

    int_type overflow(int_type c = traits_type::eof()) override
    {
        sync();

        if (short_stream())
        {
            auto next_sector = document_.allocate_short_sector();
            document_.ssat_[static_cast<std::size_t>(chain_.back())] = next_sector;
            chain_.push_back(next_sector);
            document_.change_ |= change_bit::ssat_bit;
        }
        else
        {
            auto next_sector = document_.allocate_sector();
            document_.sat_[static_cast<std::size_t>(chain_.back())] = next_sector;
            chain_.push_back(next_sector);
            document_.change_ |= change_bit::sat_bit;
        }

        auto value = static_cast<std::uint8_t>(c);

        if (c != traits_type::eof())
        {
            current_sector_[position_ % current_sector_.size()] = value;
        }

        pbump(1);

        return traits_type::to_int_type(static_cast<char>(value));
    }

    void convert_to_long_stream()
    {
        sector_reader_.reset();

        auto num_sectors = current_sector_.size() / document_.sector_size();
        auto new_chain = document_.allocate_sectors(num_sectors);

        for (auto link : new_chain)
        {
            document_.write_sector(sector_reader_, link);
            sector_reader_.offset(sector_reader_.offset() + document_.sector_size());
        }

        current_sector_.resize(document_.sector_size(), 0);
        std::fill(current_sector_.begin(), current_sector_.end(), byte(0));

        if (entry_.start && entry_.start < compound_document_entry::dirid::end)
        {
            // TODO: deallocate short sectors here
            assert(false);
        }

        chain_ = new_chain;
        entry_.start = chain_.front();
        document_.change_ |= change_bit::dir_bit;
    }

    std::streampos seekoff(std::streamoff off, std::ios_base::seekdir way, std::ios_base::openmode) override
    {
        if (way == std::ios_base::beg)
        {
            position_ = 0;
        }
        else if (way == std::ios_base::end)
        {
            position_ = entry_.size;
        }

        if (off < 0)
        {
            if (static_cast<std::size_t>(-off) > position_)
            {
                position_ = 0;
                return static_cast<std::ptrdiff_t>(-1);
            }
            else
            {
                position_ -= static_cast<std::size_t>(-off);
            }
        }
        else if (off > 0)
        {
            if (static_cast<std::size_t>(off) + position_ > entry_.size)
            {
                position_ = entry_.size;
                return static_cast<std::ptrdiff_t>(-1);
            }
            else
            {
                position_ += static_cast<std::size_t>(off);
            }
        }

        return static_cast<std::ptrdiff_t>(position_);
    }

    std::streampos seekpos(std::streampos sp, std::ios_base::openmode) override
    {
        if (sp < 0)
        {
            position_ = 0;
        }
        else if (static_cast<std::size_t>(sp) > entry_.size)
        {
            position_ = entry_.size;
        }
        else
        {
            position_ = static_cast<std::size_t>(sp);
        }

        return static_cast<std::ptrdiff_t>(position_);
    }

private:
    compound_document_entry &entry_;
    compound_document &document_;
    binary_reader<byte> sector_reader_;
    std::vector<byte> current_sector_;
    std::size_t position_;
    sector_chain chain_;
};

compound_document_ostreambuf::~compound_document_ostreambuf()
{
    sync();
}

compound_document::compound_document(std::ostream &out)
    : change_(0),
      out_(&out),
      stream_in_(nullptr),
      stream_out_(nullptr)
{
    header_.msat.fill(secid::free);
    write_header();
    insert_entry("/Root Entry", compound_document_entry::entry_type::RootStorage);
}

compound_document::compound_document(std::istream &in)
    : change_(0),
      in_(&in),
      stream_in_(nullptr),
      stream_out_(nullptr)
{
    read_header();
    read_msat();
    read_sat();
    read_ssat();
    read_directory();
}

compound_document::~compound_document()
{
    close();
}

void compound_document::close()
{
    if (change_ & change_bit::hdr_bit)
        write_header();
    if (change_ & change_bit::msat_bit)
        write_msat();
    if (change_ & change_bit::sat_bit)
        write_sat();
    if (change_ & change_bit::ssat_bit)
        write_ssat();
    if (change_ & change_bit::dir_bit)
        write_directory();
    change_ = 0;

    stream_out_buffer_.reset(nullptr);
    for (auto &entry : entries_)
        delete entry;
    entries_.clear();
}

std::size_t compound_document::sector_size()
{
    return static_cast<std::size_t>(1) << header_.sector_size_power;
}

std::size_t compound_document::short_sector_size()
{
    return static_cast<std::size_t>(1) << header_.short_sector_size_power;
}

std::istream &compound_document::open_read_stream(const std::string &name)
{
    if (!contains_entry(name, compound_document_entry::entry_type::UserStream))
    {
        throw xlnt::exception("not found");
    }

    const auto entry_id = find_entry(name, compound_document_entry::entry_type::UserStream);
    const auto &entry = entries_.at(static_cast<std::size_t>(entry_id));

    stream_in_buffer_.reset(new compound_document_istreambuf(*entry, *this));
    stream_in_.rdbuf(stream_in_buffer_.get());

    return stream_in_;
}

std::ostream &compound_document::open_write_stream(const std::string &name)
{
    auto entry_id = contains_entry(name, compound_document_entry::entry_type::UserStream)
        ? find_entry(name, compound_document_entry::entry_type::UserStream)
        : insert_entry(name, compound_document_entry::entry_type::UserStream);
    auto &entry = entries_.at(static_cast<std::size_t>(entry_id));

    stream_out_buffer_.reset(new compound_document_ostreambuf(*entry, *this));
    stream_out_.rdbuf(stream_out_buffer_.get());

    return stream_out_;
}

template <typename T>
void compound_document::write_sector(binary_reader<T> &reader, sector_id id)
{
    out_->seekp(static_cast<std::ptrdiff_t>(sector_data_start() + sector_size() * static_cast<std::size_t>(id)));
    out_->write(reinterpret_cast<const char *>(reader.data() + reader.offset()),
        static_cast<std::ptrdiff_t>(std::min(sector_size(), reader.bytes() - reader.offset())));
}

template <typename T>
void compound_document::write_short_sector(binary_reader<T> &reader, sector_id id)
{
    auto chain = follow_chain(entries_[0]->start, sat_);
    auto sector_id = chain[static_cast<std::size_t>(id) / (sector_size() / short_sector_size())];
    auto sector_offset = static_cast<std::size_t>(id) % (sector_size() / short_sector_size()) * short_sector_size();
    out_->seekp(static_cast<std::ptrdiff_t>(sector_data_start() + sector_size() * static_cast<std::size_t>(sector_id) + sector_offset));
    out_->write(reinterpret_cast<const char *>(reader.data() + reader.offset()),
        static_cast<std::ptrdiff_t>(std::min(short_sector_size(), reader.bytes() - reader.offset())));
}

template <typename T>
void compound_document::read_sector(sector_id id, binary_writer<T> &writer)
{
    in_->seekg(static_cast<std::ptrdiff_t>(sector_data_start() + sector_size() * static_cast<std::size_t>(id)));
    std::vector<byte> sector(sector_size(), 0);
    in_->read(reinterpret_cast<char *>(sector.data()), static_cast<std::ptrdiff_t>(sector_size()));
    writer.append(sector);
}

template <typename T>
void compound_document::read_sector_chain(sector_id start, binary_writer<T> &writer)
{
    for (auto link : follow_chain(start, sat_))
    {
        read_sector(link, writer);
    }
}

template <typename T>
void compound_document::read_sector_chain(sector_id start, binary_writer<T> &writer, sector_id offset, std::size_t count)
{
    auto chain = follow_chain(start, sat_);

    for (auto i = std::size_t(0); i < count; ++i)
    {
        read_sector(chain[offset + i], writer);
    }
}

template <typename T>
void compound_document::read_short_sector(sector_id id, binary_writer<T> &writer)
{
    const auto container_chain = follow_chain(entries_[0]->start, sat_);
    auto container = std::vector<byte>();
    auto container_writer = binary_writer<byte>(container);

    for (auto sector : container_chain)
    {
        read_sector(sector, container_writer);
    }

    auto container_reader = binary_reader<byte>(container);
    container_reader.offset(static_cast<std::size_t>(id) * short_sector_size());

    writer.append(container_reader, short_sector_size());
}

template <typename T>
void compound_document::read_short_sector_chain(sector_id start, binary_writer<T> &writer)
{
    for (auto link : follow_chain(start, ssat_))
    {
        read_short_sector(link, writer);
    }
}

template <typename T>
void compound_document::read_short_sector_chain(sector_id start, binary_writer<T> &writer, sector_id offset, std::size_t count)
{
    auto chain = follow_chain(start, ssat_);

    for (auto i = std::size_t(0); i < count; ++i)
    {
        read_short_sector(chain[offset + i], writer);
    }
}

sector_id compound_document::allocate_sector()
{
    const auto sectors_per_sector = sector_size() / sizeof(sector_id);
    auto next_free_iter = std::find(sat_.begin(), sat_.end(), secid::free);

    if (next_free_iter == sat_.end())
    {
        auto next_msat_index = header_.num_msat_sectors;
        auto new_sat_sector_id = sector_id(sat_.size());

        sat_.resize(sat_.size() + sectors_per_sector, secid::free);
        sat_[static_cast<std::size_t>(new_sat_sector_id)] = secid::sat;

        auto sat_reader = binary_reader<sector_id>(sat_);
        sat_reader.offset(next_msat_index * sectors_per_sector);
        write_sector(sat_reader, new_sat_sector_id);

        ++header_.num_msat_sectors;
        msat_.push_back(new_sat_sector_id);

        if (msat_.size() <= 109)
        {
            header_.msat[msat_.size() - 1] = new_sat_sector_id;
        }
        else
        {
            auto i = ((msat_.size() + (header_.num_extra_msat_sectors ? (header_.num_extra_msat_sectors - 1) : 0) - 109 + sectors_per_sector - 1) / sectors_per_sector);
            if (i > header_.num_extra_msat_sectors)
            {
                // 额外的 msat 项数量占用的扇区数大于已有 extra 扇区数时，需要新分配 extra 扇区
                ++new_sat_sector_id;
                ++header_.num_extra_msat_sectors;
                extra_msat_.push_back(new_sat_sector_id);
                if (header_.extra_msat_start == secid::end_of_chain)
                    header_.extra_msat_start = new_sat_sector_id;

                sat_[static_cast<std::size_t>(new_sat_sector_id)] = secid::msat;

                auto empty_sector = std::vector<byte>(sector_size());
                auto empty_sector_reader = binary_reader<byte>(empty_sector);
                write_sector(empty_sector_reader, new_sat_sector_id);
            }
        }

        change_ |= change_bit::hdr_bit | change_bit::msat_bit;

        next_free_iter = std::find(sat_.begin(), sat_.end(), secid::free);
    }

    auto next_free = sector_id(next_free_iter - sat_.begin());
    sat_[static_cast<std::size_t>(next_free)] = secid::end_of_chain;

    change_ |= change_bit::sat_bit;

    auto empty_sector = std::vector<byte>(sector_size());
    auto empty_sector_reader = binary_reader<byte>(empty_sector);
    write_sector(empty_sector_reader, next_free);

    return next_free;
}

sector_chain compound_document::allocate_sectors(std::size_t count)
{
    if (count == std::size_t(0)) return {};

    auto chain = sector_chain();
    auto current = allocate_sector();

    for (auto i = std::size_t(1); i < count; ++i)
    {
        chain.push_back(current);
        auto next = allocate_sector();
        sat_[static_cast<std::size_t>(current)] = next;
        current = next;
    }

    chain.push_back(current);
    change_ |= change_bit::sat_bit;

    return chain;
}

sector_chain compound_document::follow_chain(sector_id start, const sector_chain &table)
{
    auto chain = sector_chain();
    auto current = start;

    while (current < secid::msat)
    {
        chain.push_back(current);
        current = table[static_cast<std::size_t>(current)];
    }

    return chain;
}

sector_chain compound_document::allocate_short_sectors(std::size_t count)
{
    if (count == std::size_t(0)) return {};

    auto chain = sector_chain();
    auto current = allocate_short_sector();

    for (auto i = std::size_t(1); i < count; ++i)
    {
        chain.push_back(current);
        auto next = allocate_short_sector();
        ssat_[static_cast<std::size_t>(current)] = next;
        current = next;
    }

    chain.push_back(current);
    change_ |= change_bit::ssat_bit;

    return chain;
}

sector_id compound_document::allocate_short_sector()
{
    const auto sectors_per_sector = sector_size() / sizeof(sector_id);
    auto next_free_iter = std::find(ssat_.begin(), ssat_.end(), secid::free);

    if (next_free_iter == ssat_.end())
    {
        auto new_ssat_sector_id = allocate_sector();

        if (header_.ssat_start == secid::end_of_chain)
        {
            header_.ssat_start = new_ssat_sector_id;
        }
        else
        {
            auto ssat_chain = follow_chain(header_.ssat_start, sat_);
            sat_[static_cast<std::size_t>(ssat_chain.back())] = new_ssat_sector_id;
            change_ |= change_bit::sat_bit;
        }
        ++header_.num_ssat_sectors;
        change_ |= change_bit::hdr_bit;

        auto old_size = ssat_.size();
        ssat_.resize(old_size + sectors_per_sector, secid::free);

        auto ssat_reader = binary_reader<sector_id>(ssat_);
        ssat_reader.offset(old_size / sectors_per_sector);
        write_sector(ssat_reader, new_ssat_sector_id);

        next_free_iter = std::find(ssat_.begin(), ssat_.end(), secid::free);
    }

    auto next_free = sector_id(next_free_iter - ssat_.begin());
    ssat_[static_cast<std::size_t>(next_free)] = secid::end_of_chain;

    change_ |= change_bit::ssat_bit;

    const auto short_sectors_per_sector = sector_size() / short_sector_size();
    const auto required_container_sectors = static_cast<std::size_t>(next_free) / short_sectors_per_sector + std::size_t(1);

    if (required_container_sectors > 0)
    {
        if (entries_[0]->start <= 0)
        {
            entries_[0]->start = allocate_sector();
        }

        auto container_chain = follow_chain(entries_[0]->start, sat_);

        if (required_container_sectors > container_chain.size())
        {
            sat_[static_cast<std::size_t>(container_chain.back())] = allocate_sector();
            change_ |= change_bit::sat_bit;
        }
    }
    entries_[0]->size += short_sector_size();
    change_ |= change_bit::dir_bit;

    return next_free;
}

directory_id compound_document::next_empty_entry()
{
    auto entry_id = directory_id(0);

    for (; entry_id < directory_id(entries_.size()); ++entry_id)
    {
        auto &entry = entries_[static_cast<std::size_t>(entry_id)];

        if (entry->type == compound_document_entry::entry_type::Empty)
        {
            return entry_id;
        }
    }

    // entry_id is now equal to entries_.size()

    if (header_.directory_start >= secid::end_of_chain)
    {
        header_.directory_start = allocate_sector();
    }
    else
    {
        auto directory_chain = follow_chain(header_.directory_start, sat_);
        sat_[static_cast<std::size_t>(directory_chain.back())] = allocate_sector();
        change_ |= change_bit::sat_bit;
    }

    const auto entries_per_sector = sector_size()
        / sizeof(compound_document_entry);

    for (auto i = std::size_t(0); i < entries_per_sector; ++i)
    {
        entries_.push_back(new compound_document_entry());
    }
    change_ |= change_bit::dir_bit;

    return entry_id;
}

directory_id compound_document::insert_entry(
    const std::string &name,
    compound_document_entry::entry_type type)
{
    auto entry_id = next_empty_entry();
    auto entry = entries_[static_cast<std::size_t>(entry_id)];

    auto parent_id = directory_id(0);
    auto split = split_path(name);
    auto filename = split.back();
    split.pop_back();

    if (!split.empty())
    {
        auto parent_path = join_path(split);
        parent_id = find_entry(parent_path, compound_document_entry::entry_type::UserStorage);

        if (parent_id == dirid::end)
        {
            parent_id = insert_entry(parent_path, compound_document_entry::entry_type::UserStorage);
            entry_id = next_empty_entry();
            entry = entries_[static_cast<std::size_t>(entry_id)];
        }

        parent_storage_[entry_id] = parent_id;
    }

    entry->name(filename);
    entry->type = type;

    tree_insert(entry_id, parent_id);
    change_ |= change_bit::dir_bit;

    return entry_id;
}

std::size_t compound_document::sector_data_start()
{
    return sizeof(compound_document_header);
}

bool compound_document::contains_entry(const std::string &path,
    compound_document_entry::entry_type type)
{
    return find_entry(path, type) < dirid::end;
}

directory_id compound_document::find_entry(const std::string &name,
    compound_document_entry::entry_type type)
{
    if (type == compound_document_entry::entry_type::RootStorage
        && (name == "/" || name == "/Root Entry")) return 0;

    auto entry_id = directory_id(0);

    for (auto &entry : entries_)
    {
        if (entry->type == type && tree_path(entry_id) == name)
        {
            return entry_id;
        }

        ++entry_id;
    }

    return dirid::end;
}

void compound_document::print_directory()
{
    auto entry_id = directory_id(0);

    for (auto &entry : entries_)
    {
        if (entry->type == compound_document_entry::entry_type::UserStream)
        {
            std::cout << tree_path(entry_id) << std::endl;
        }

        ++entry_id;
    }
}

void compound_document::write_directory()
{
    for (auto entry_id = std::size_t(0); entry_id < entries_.size(); ++entry_id)
    {
        write_entry(directory_id(entry_id));
    }
}

void compound_document::read_directory()
{
    const auto entries_per_sector = sector_size() / sizeof(compound_document_entry);
    const auto num_entries = follow_chain(header_.directory_start, sat_).size() * entries_per_sector;

    for (auto entry_id = std::size_t(0); entry_id < num_entries; ++entry_id)
    {
        entries_.push_back(new compound_document_entry());
        read_entry(directory_id(entry_id));
    }

    auto stack = std::vector<directory_id>();
    auto storage_siblings = std::vector<directory_id>();
    auto stream_siblings = std::vector<directory_id>();

    auto directory_stack = std::vector<directory_id>();
    directory_stack.push_back(directory_id(0));

    while (!directory_stack.empty())
    {
        auto current_storage_id = directory_stack.back();
        directory_stack.pop_back();

        if (tree_child(current_storage_id) == dirid::end) continue;

        auto storage_stack = std::vector<directory_id>();
        auto storage_root_id = tree_child(current_storage_id);
        parent_[storage_root_id] = dirid::end;
        storage_stack.push_back(storage_root_id);

        while (!storage_stack.empty())
        {
            auto current_entry_id = storage_stack.back();
            auto current_entry = entries_[static_cast<std::size_t>(current_entry_id)];
            storage_stack.pop_back();

            parent_storage_[current_entry_id] = current_storage_id;

            if (current_entry->type == compound_document_entry::entry_type::UserStorage)
            {
                directory_stack.push_back(current_entry_id);
            }

            if (tree_left(current_entry_id) < dirid::end)
            {
                storage_stack.push_back(tree_left(current_entry_id));
                tree_parent(tree_left(current_entry_id)) = current_entry_id;
            }

            if (tree_right(current_entry_id) < dirid::end)
            {
                storage_stack.push_back(tree_right(current_entry_id));
                tree_parent(tree_right(current_entry_id)) = current_entry_id;
            }
        }
    }
}

void compound_document::tree_insert(directory_id new_id, directory_id storage_id)
{
    using entry_color = compound_document_entry::entry_color;

    parent_storage_[new_id] = storage_id;

    tree_left(new_id) = dirid::end;
    tree_right(new_id) = dirid::end;

    if (tree_root(new_id) == dirid::end)
    {
        if (new_id != 0)
        {
            tree_root(new_id) = new_id;
        }

        tree_color(new_id) = entry_color::Black;
        tree_parent(new_id) = dirid::end;

        return;
    }

    // normal tree insert
    // (will probably unbalance the tree, fix after)
    directory_id x = tree_root(new_id);
    directory_id y = dirid::end;

    while (x < dirid::end)
    {
        y = x;

        if (compare_keys(tree_key(new_id), tree_key(x)) > 0)
        {
            x = tree_right(x);
        }
        else
        {
            x = tree_left(x);
        }
    }

    tree_parent(new_id) = y;

    if (compare_keys(tree_key(new_id), tree_key(y)) > 0)
    {
        tree_right(y) = new_id;
    }
    else
    {
        tree_left(y) = new_id;
    }

    tree_insert_fixup(new_id);
}

std::string compound_document::tree_path(directory_id id)
{
    auto storage_id = parent_storage_[id];
    auto result = std::list<std::string>();

    while (storage_id && storage_id < dirid::end)
    {
        result.push_front(entries_[static_cast<std::size_t>(storage_id)]->name());
        storage_id = parent_storage_[storage_id];
    }

    return join_path(result).append("/").append(entries_[static_cast<std::size_t>(id)]->name());
}

void compound_document::tree_rotate_left(directory_id x)
{
    auto y = tree_right(x);

    // turn y's left subtree into x's right subtree
    tree_right(x) = tree_left(y);

    if (tree_left(y) != dirid::end)
    {
        tree_parent(tree_left(y)) = x;
    }

    // link x's parent to y
    tree_parent(y) = tree_parent(x);

    if (tree_parent(x) == dirid::end)
    {
        tree_root(x) = y;
    }
    else if (x == tree_left(tree_parent(x)))
    {
        tree_left(tree_parent(x)) = y;
    }
    else
    {
        tree_right(tree_parent(x)) = y;
    }

    // put x on y's left
    tree_left(y) = x;
    tree_parent(x) = y;
}

void compound_document::tree_rotate_right(directory_id y)
{
    auto x = tree_left(y);

    // turn x's right subtree into y's left subtree
    tree_left(y) = tree_right(x);

    if (tree_right(x) != dirid::end)
    {
        tree_parent(tree_right(x)) = y;
    }

    // link y's parent to x
    tree_parent(x) = tree_parent(y);

    if (tree_parent(y) == dirid::end)
    {
        tree_root(y) = x;
    }
    else if (y == tree_left(tree_parent(y)))
    {
        tree_left(tree_parent(y)) = x;
    }
    else
    {
        tree_right(tree_parent(y)) = x;
    }

    // put y on x's right
    tree_right(x) = y;
    tree_parent(y) = x;
}

void compound_document::tree_insert_fixup(directory_id x)
{
    using entry_color = compound_document_entry::entry_color;

    tree_color(x) = entry_color::Red;

    while (x != tree_root(x) && tree_color(tree_parent(x)) == entry_color::Red)
    {
        if (tree_parent(x) == tree_left(tree_parent(tree_parent(x))))
        {
            auto y = tree_right(tree_parent(tree_parent(x)));

            if (y < dirid::end && tree_color(y) == entry_color::Red)
            {
                // case 1
                tree_color(tree_parent(x)) = entry_color::Black;
                tree_color(y) = entry_color::Black;
                tree_color(tree_parent(tree_parent(x))) = entry_color::Red;
                x = tree_parent(tree_parent(x));
            }
            else
            {
                if (x == tree_right(tree_parent(x)))
                {
                    // case 2
                    x = tree_parent(x);
                    tree_rotate_left(x);
                }

                // case 3
                tree_color(tree_parent(x)) = entry_color::Black;
                tree_color(tree_parent(tree_parent(x))) = entry_color::Red;
                tree_rotate_right(tree_parent(tree_parent(x)));
            }
        }
        else // same as above with left and right switched
        {
            auto y = tree_left(tree_parent(tree_parent(x)));

            if (y < dirid::end && tree_color(y) == entry_color::Red)
            {
                //case 1
                tree_color(tree_parent(x)) = entry_color::Black;
                tree_color(y) = entry_color::Black;
                tree_color(tree_parent(tree_parent(x))) = entry_color::Red;
                x = tree_parent(tree_parent(x));
            }
            else
            {
                if (x == tree_left(tree_parent(x)))
                {
                    // case 2
                    x = tree_parent(x);
                    tree_rotate_right(x);
                }

                // case 3
                tree_color(tree_parent(x)) = entry_color::Black;
                tree_color(tree_parent(tree_parent(x))) = entry_color::Red;
                tree_rotate_left(tree_parent(tree_parent(x)));
            }
        }
    }

    tree_color(tree_root(x)) = entry_color::Black;
}

directory_id &compound_document::tree_left(directory_id id)
{
    return entries_[static_cast<std::size_t>(id)]->prev;
}

directory_id &compound_document::tree_right(directory_id id)
{
    return entries_[static_cast<std::size_t>(id)]->next;
}

directory_id &compound_document::tree_parent(directory_id id)
{
    return parent_[id];
}

directory_id &compound_document::tree_root(directory_id id)
{
    return tree_child(parent_storage_[id]);
}

directory_id &compound_document::tree_child(directory_id id)
{
    return entries_[static_cast<std::size_t>(id)]->child;
}

std::string compound_document::tree_key(directory_id id)
{
    return entries_[static_cast<std::size_t>(id)]->name();
}

compound_document_entry::entry_color &compound_document::tree_color(directory_id id)
{
    return entries_[static_cast<std::size_t>(id)]->color;
}

void compound_document::read_header()
{
    in_->seekg(0, std::ios::beg);
    in_->read(reinterpret_cast<char *>(&header_), sizeof(compound_document_header));
}

void compound_document::read_msat()
{
    msat_.clear();

    for (size_t i = 0; i < 109; ++i)
    {
        if (header_.msat[i] < secid::msat)
            msat_.push_back(header_.msat[i]);
    }

    if (header_.num_msat_sectors > 109 && header_.num_extra_msat_sectors)
    {
        auto msat_sector = header_.extra_msat_start;
        auto msat_writer = binary_writer<sector_id>(msat_);

        for (auto i = std::uint32_t(0); i < header_.num_extra_msat_sectors; ++i)
        {
            read_sector(msat_sector, msat_writer);

            msat_sector = msat_.back();
            msat_.pop_back();
        }
    }
}

void compound_document::read_sat()
{
    sat_.clear();
    auto sat_writer = binary_writer<sector_id>(sat_);

    for (auto msat_sector : msat_)
    {
        read_sector(msat_sector, sat_writer);
    }
}

void compound_document::read_ssat()
{
    ssat_.clear();
    auto ssat_writer = binary_writer<sector_id>(ssat_);

    for (auto ssat_sector : follow_chain(header_.ssat_start, sat_))
    {
        read_sector(ssat_sector, ssat_writer);
    }
}

void compound_document::read_entry(directory_id id)
{
    const auto directory_chain = follow_chain(header_.directory_start, sat_);
    const auto entries_per_sector = sector_size() / sizeof(compound_document_entry);
    const auto directory_sector = directory_chain[static_cast<std::size_t>(id) / entries_per_sector];
    const auto offset = sector_size() * static_cast<std::size_t>(directory_sector)
        + ((static_cast<std::size_t>(id) % entries_per_sector) * sizeof(compound_document_entry));

    in_->seekg(static_cast<std::ptrdiff_t>(sector_data_start() + offset), std::ios::beg);
    in_->read(reinterpret_cast<char *>(entries_[static_cast<std::size_t>(id)]), sizeof(compound_document_entry));
}

void compound_document::write_header()
{
    out_->seekp(0, std::ios::beg);
    out_->write(reinterpret_cast<char *>(&header_), sizeof(compound_document_header));
}

void compound_document::write_msat()
{
    if (!header_.num_extra_msat_sectors)
        return;

    const auto sectors_per_sector = sector_size() / sizeof(sector_id);
    auto extra_msat_sector = std::vector<sector_id>(sectors_per_sector, secid::free);
    auto sector_reader = binary_reader<sector_id>(extra_msat_sector);

    for (size_t msat_offset = 109, num_msat = msat_.size(), chain_index = 0, num_sectors = extra_msat_.size();
         msat_offset < num_msat && chain_index < num_sectors; ++chain_index)
    {
        auto count = num_msat - msat_offset;
        std::fill(extra_msat_sector.begin(), extra_msat_sector.end(), secid::free);
        if (count > sectors_per_sector)
        {
            count = sectors_per_sector - 1;
            extra_msat_sector.back() = extra_msat_[chain_index + 1];
        }
        std::copy(msat_.begin() + msat_offset, msat_.begin() + msat_offset + count, extra_msat_sector.begin());
        msat_offset += count;

        write_sector(sector_reader, extra_msat_[chain_index]);
        sector_reader.offset(sector_reader.offset() + sectors_per_sector);
    }
}

void compound_document::write_sat()
{
    const auto sectors_per_sector = sector_size() / sizeof(sector_id);
    auto sector_reader = binary_reader<sector_id>(sat_);

    for (auto sat_sector : msat_)
    {
        write_sector(sector_reader, sat_sector);
        sector_reader.offset(sector_reader.offset() + sectors_per_sector);
    }
}

void compound_document::write_ssat()
{
    const auto sectors_per_sector = sector_size() / sizeof(sector_id);
    auto sector_reader = binary_reader<sector_id>(ssat_);

    for (auto ssat_sector : follow_chain(header_.ssat_start, sat_))
    {
        write_sector(sector_reader, ssat_sector);
        sector_reader.offset(sector_reader.offset() + sectors_per_sector);
    }
}

void compound_document::write_entry(directory_id id)
{
    const auto directory_chain = follow_chain(header_.directory_start, sat_);
    const auto entries_per_sector = sector_size() / sizeof(compound_document_entry);
    const auto directory_sector = directory_chain[static_cast<std::size_t>(id) / entries_per_sector];
    const auto offset = sector_data_start() + sector_size() * static_cast<std::size_t>(directory_sector)
        + ((static_cast<std::size_t>(id) % entries_per_sector) * sizeof(compound_document_entry));

    out_->seekp(static_cast<std::ptrdiff_t>(offset), std::ios::beg);
    out_->write(reinterpret_cast<char *>(entries_[static_cast<std::size_t>(id)]), sizeof(compound_document_entry));
}

} // namespace detail
} // namespace xlnt
