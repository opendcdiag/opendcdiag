/*
 * Copyright 2025 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef INC_TOPOLOGY_CPU_H
#define INC_TOPOLOGY_CPU_H

#include "sandstone.h"
#include "cpu_device.h"
#include "topology.h"

#include "gettid.h"

#include <algorithm>
#include <barrier>
#include <functional>
#include <mutex>
#include <span>

using EnabledDevices = LogicalProcessorSet;

class Topology
{
    template <auto Field, typename Source> struct CoreViewGroupedByField;
    template <auto Field, typename Source> struct CoreGroupingView;

public:
    using Thread = cpu_info_t;
    struct Core
    {
        std::span<const Thread> threads;
        int id() const
        { return threads.size() ? threads.front().core_id : -1; }
    };

    // Non-owning version of CoreGrouping
    struct CoreGroupingViewBase
    {
        std::span<const Core> cores;

        using Module = CoreGroupingView<&Thread::module_id, CoreGroupingViewBase>;
        using ModuleView = CoreViewGroupedByField<&Thread::module_id, CoreGroupingViewBase>;
        ModuleView modules() const noexcept;

        using Die = CoreGroupingView<&Thread::die_id, CoreGroupingViewBase>;
        using DieView = CoreViewGroupedByField<&Thread::die_id, CoreGroupingViewBase>;
        DieView dies() const noexcept;

        using NumaDomain = CoreGroupingView<&Thread::numa_id, CoreGroupingViewBase>;
        using NumaDomainView = CoreViewGroupedByField<&Thread::numa_id, CoreGroupingViewBase>;
        NumaDomainView numa_domains() const noexcept;
    };

    struct CoreGrouping
    {
        std::vector<Core> cores;

        /// Size in bytes of the last-level (L3) cache attributable to this grouping.
        size_t l3_cache_size = 0;

        using Module = CoreGroupingView<&Thread::module_id, CoreGrouping>;
        using ModuleView = CoreViewGroupedByField<&Thread::module_id, CoreGrouping>;
        ModuleView modules() const noexcept;

        using Die = CoreGroupingView<&Thread::die_id, CoreGrouping>;
        using DieView = CoreViewGroupedByField<&Thread::die_id, CoreGrouping>;
        DieView dies() const noexcept;

        using NumaDomain = CoreGroupingView<&Thread::numa_id, CoreGrouping>;
        using NumaDomainView = CoreViewGroupedByField<&Thread::numa_id, CoreGrouping>;
        NumaDomainView numa_domains() const noexcept;
    };

    struct Package : CoreGrouping
    {
        // any grouping inside of a package (see build_topology() for rules)
        std::vector<CoreGrouping> groups;
        int id() const
        {
            return cores.size() ? cores.front().threads.front().package_id : -1;
        }
    };

    std::vector<Package> packages;

    bool isValid() const
    {
        return !packages.empty();
    }

    std::string build_failure_mask(const struct test *test) const;

    static const Topology &topology();
    static Topology build_topology(std::span<const Thread> threads);
    struct Data;
    Data clone() const;

    // using Core = Core;
    using CoreView = CoreViewGroupedByField<&Thread::core_id, Package>;
    CoreView cores() const noexcept;

    using Module = CoreGroupingView<&Thread::module_id, Package>;
    using ModuleView = CoreViewGroupedByField<&Thread::module_id, Package>;
    ModuleView modules() const noexcept;

    using Die = CoreGroupingView<&Thread::die_id, Package>;
    using DieView = CoreViewGroupedByField<&Thread::die_id, Package>;
    DieView dies() const noexcept;

    using NumaDomain = CoreGroupingView<&Thread::numa_id, Package>;
    using NumaDomainView = CoreViewGroupedByField<&Thread::numa_id, Package>;
    NumaDomainView numa_domains() const noexcept;
};

template <auto Field, typename Source>
struct Topology::CoreGroupingView : public CoreGroupingViewBase
{
    int id() const noexcept { return cores.size() ? cores[0].threads[0].*Field : -1; }
};

template <auto Field, typename Source> struct Topology::CoreViewGroupedByField :
        public std::ranges::view_interface<CoreViewGroupedByField<Field, Source>>
{
private:
    // If Source is Package, we are viewing the whole-system;
    // if it is Core, we are inside of a package or a subdivision thereof.
    using SourceSpan = std::span<const Source>;
    using CoreGroupingView = Topology::CoreGroupingView<Field, Source>;

    static constexpr bool is_view_of_cores = (Field == &Thread::core_id);

    static int id_for(const Core &c) noexcept
    { return c.threads[0].*Field; }

public:
    using element_type = std::conditional_t<is_view_of_cores, Core, CoreGroupingView>;
    using value_type = element_type;
    using size_type = size_t;
    using difference_type = ptrdiff_t;
    using pointer = const element_type *;
    using const_pointer = const element_type *;
    using reference = const element_type &;
    using const_reference = const element_type &;

    struct iterator {
        using iterator_category = std::forward_iterator_tag;
        using value_type = CoreViewGroupedByField::element_type;
        using difference_type = ptrdiff_t;
        using pointer = const value_type *;
        using reference = const value_type &;

        constexpr iterator() noexcept = default;

        const_pointer operator->() const noexcept
        {
            if constexpr (is_view_of_cores)
                return current.cores.data();        // const Core *
            else
                return &current;                    // const value_type *
        }
        const_reference operator*() const noexcept
        { return *operator->(); }

        iterator &operator++() noexcept
        {
            auto next = current.cores.end();
            if (next == segment().end()) {
                // Move to the next grouping.
                groupings = groupings.subspan(1);
                if (groupings.empty()) {
                    current.cores = {};             // the end
                    return *this;
                }
                next = segment().begin();
            }

            current.cores = { next, find_end(next) };
            return *this;
        }

        iterator operator++(int) noexcept
        {
            iterator tmp = *this;
            operator++();
            return tmp;
        }

        friend bool operator==(iterator l, iterator r) noexcept
        {
            if (l.current.cores.begin() != r.current.cores.begin())
                return false;
            assert(l.current.cores.end() == r.current.cores.end());
            assert(l.groupings.begin() == r.groupings.begin());
            assert(l.groupings.end() == r.groupings.end());
            return true;
        }
        friend bool operator==(iterator it, std::default_sentinel_t) noexcept
        { return it.current.cores.empty(); }
    private:
        friend struct CoreViewGroupedByField<Field, Source>;
        SourceSpan groupings;
        CoreGroupingView current = {};

        constexpr explicit iterator(SourceSpan src) noexcept : groupings(src)
        {
            if (groupings.empty())
                return;
            if (std::span seg = segment(); !seg.empty())
                current.cores = std::span<const Core>(seg.begin(), find_end(seg.begin()));
        }

        constexpr std::span<const Core> segment() const noexcept
        {
            return groupings.front().cores;
        }

        constexpr auto find_end(std::span<const Core>::iterator ptr) const noexcept
        {
            auto stop = segment().end();
            int curr_id = id_for(*ptr);
            for ( ; ptr != stop; ++ptr) {
                if (id_for(*ptr) != curr_id)
                    break;
            }
            return ptr;
        };
    };
    using const_iterator = iterator;

    constexpr iterator begin() const noexcept       { return iterator(source); }
    constexpr std::default_sentinel_t end() const noexcept { return {}; }

    constexpr CoreViewGroupedByField() = default;
    constexpr explicit CoreViewGroupedByField(SourceSpan src) noexcept : source(src) {}
    constexpr explicit CoreViewGroupedByField(const Source *src) noexcept : source(src, 1) {}
private:
    SourceSpan source;
};

inline auto Topology::CoreGroupingViewBase::modules() const noexcept -> ModuleView
{ return ModuleView(this); }
inline auto Topology::CoreGroupingViewBase::dies() const noexcept -> DieView
{ return DieView(this); }
inline auto Topology::CoreGroupingViewBase::numa_domains() const noexcept -> NumaDomainView
{ return NumaDomainView(this); }

inline auto Topology::CoreGrouping::modules() const noexcept -> ModuleView
{ return ModuleView(this); }
inline auto Topology::CoreGrouping::dies() const noexcept -> DieView
{ return DieView(this); }
inline auto Topology::CoreGrouping::numa_domains() const noexcept -> NumaDomainView
{ return NumaDomainView(this); }

inline auto Topology::numa_domains() const noexcept -> NumaDomainView
{ return NumaDomainView(packages); }
inline auto Topology::dies() const noexcept -> DieView
{ return DieView(std::span<const Package>(packages)); }
inline auto Topology::modules() const noexcept -> ModuleView
{ return ModuleView(std::span<const Package>(packages)); }
inline auto Topology::cores() const noexcept -> CoreView
{ return CoreView(std::span<const Package>(packages)); }

struct Topology::Data
{
    // this type is move-only (not copyable)
    Data() = default;
    Data(const Data &) = delete;
    Data(Data &&) = default;
    Data &operator=(const Data &) = delete;
    Data &operator=(Data &&) = default;

    std::vector<Package> packages;
    std::vector<Topology::Thread> all_threads;
};

struct HardwareInfo
{
    // information for CPUs
    struct PackageInfo {
        int id;
        uint64_t ppin;
    };

    std::vector<PackageInfo> package_infos;
    uint16_t model = 0;
    uint8_t family = 0;
    uint8_t stepping = 0;

    const PackageInfo *find_package_id(int pkgid) const
    {
        auto it = std::find_if(package_infos.cbegin(), package_infos.cend(),
                               [pkgid](const PackageInfo &pi) { return pkgid == pi.id; });
        return it == package_infos.cend() ? nullptr : std::to_address(it);
    }
};

class BarrierDeviceScheduler : public DeviceScheduler
{
public:
    void reschedule_to_next_device() override;
    void finish_reschedule() override;

private:
    struct GroupInfo
    {
        std::barrier<std::function<void()>> *barrier;
        std::vector<pid_t> tid;     // Keep track of all members tid
        std::vector<int> next_cpu;  // Keep track of cpus on the group

        GroupInfo(int members_per_group, std::function<void()> on_completion)
        {
            barrier = new std::barrier<std::function<void()>>(members_per_group, std::move(on_completion));
            tid.resize(members_per_group);
            next_cpu.resize(members_per_group);
        }

        ~GroupInfo()
        {
            delete barrier;
        }
    };

    const int members_per_group = 2; // TODO: Make it configurable
    std::vector<GroupInfo> groups;
    std::mutex groups_mutex;
};

class QueueDeviceScheduler : public DeviceScheduler
{
public:
    void reschedule_to_next_device() override;
    void finish_reschedule() override {}

private:
    void shuffle_queue();

    int q_idx = 0;
    std::vector<int> queue;
    std::mutex q_mutex;
};

class RandomDeviceScheduler : public DeviceScheduler
{
public:
    void reschedule_to_next_device() override;
    void finish_reschedule() override {}
};

#endif /* INC_TOPOLOGY_CPU_H */
