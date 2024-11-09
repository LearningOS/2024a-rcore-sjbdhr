//! Process management syscalls

use crate::{
    config::{MAX_SYSCALL_NUM, PAGE_SIZE}, mm::MapPermission, task::{
        change_program_brk, current_user_token, exit_current_and_run_next, get_current_task_basic, mmp, munmap, suspend_current_and_run_next, TaskStatus
    }, timer::get_time_us
};

use crate::mm::write_in_by_va;
use crate::timer::get_time_ms;

#[repr(C)]
#[derive(Debug)]
pub struct TimeVal {
    pub sec: usize,
    pub usec: usize,
}

/// Task information
#[allow(dead_code)]
pub struct TaskInfo {
    /// Task status in it's life cycle
    status: TaskStatus,
    /// The numbers of syscall called by task
    syscall_times: [u32; MAX_SYSCALL_NUM],
    /// Total running time of task
    time: usize,
}

/// task exits and submit an exit code
pub fn sys_exit(_exit_code: i32) -> ! {
    trace!("kernel: sys_exit");
    exit_current_and_run_next();
    panic!("Unreachable in sys_exit!");
}

/// current task gives up resources for other tasks
pub fn sys_yield() -> isize {
    trace!("kernel: sys_yield");
    suspend_current_and_run_next();
    0
}

/// YOUR JOB: get time with second and microsecond
/// HINT: You might reimplement it with virtual memory management.
/// HINT: What if [`TimeVal`] is splitted by two pages ?
pub fn sys_get_time(_ts: *mut TimeVal, _tz: usize) -> isize {
    trace!("kernel: sys_get_time");
    let us = get_time_us();

    let sec = us / 1_000_000;
    let usec = us % 1_000_000;

    let current_time = TimeVal { sec, usec };
    let time_val_bytes = unsafe {
        let ptr = &current_time as *const TimeVal as *const u8;
        core::slice::from_raw_parts(ptr, core::mem::size_of::<TimeVal>())
    };
    
    let token = current_user_token();

    write_in_by_va(token, _ts as usize, time_val_bytes);

    0 // 成功返回 0
}

/// YOUR JOB: Finish sys_task_info to pass testcases
/// HINT: You might reimplement it with virtual memory management.
/// HINT: What if [`TaskInfo`] is splitted by two pages ?
pub fn sys_task_info(_ti: *mut TaskInfo) -> isize {
    trace!("kernel: sys_task_info NOT IMPLEMENTED YET!");
    
    let status;
    let start_time;
    let syscall_times: [u32; MAX_SYSCALL_NUM];
    (status, start_time, syscall_times) = get_current_task_basic();
    let syscall_times:[u32; MAX_SYSCALL_NUM] = syscall_times.try_into().unwrap();


    let task_info: TaskInfo = TaskInfo { status, syscall_times, time : (get_time_ms() - start_time) };
    let val_bytes = unsafe {
        let ptr = &task_info as *const TaskInfo as *const u8;
        core::slice::from_raw_parts(ptr, core::mem::size_of::<TaskInfo>())
    };

    let token = current_user_token();

    write_in_by_va(token, _ti as usize, val_bytes);

    0

}

// YOUR JOB: Implement mmap.
pub fn sys_mmap(start: usize, len: usize, port: usize) -> isize {
    trace!("kernel: sys_mmap NOT IMPLEMENTED YET!");
     // Check if start address is page aligned
    if start % PAGE_SIZE != 0 {
        return -1;
    }

    // Check if port has invalid bits set or if all permission bits are zero
    if port & !0x7 != 0 || port & 0x7 == 0 {
        return -1;
    }

    // Align length to page size
    let len_aligned = ((len + PAGE_SIZE - 1) / PAGE_SIZE) * PAGE_SIZE;
    if len_aligned == 0 {
        return -1;
    }

    // Convert port to MapPermission
    let mut map_permission = MapPermission::empty();
    if (port & 0x1) != 0 {
        map_permission |= MapPermission::R;
    }
    if (port & 0x2) != 0 {
        map_permission |= MapPermission::W;
    }
    if (port & 0x4) != 0 {
        map_permission |= MapPermission::X;
    }
    map_permission |= MapPermission::U;

    trace!("kernel: sys_mmap: start={:#x}, len={:#x}, port=0b{:03b}, map_permission={:?}", start, len_aligned, port, map_permission);
    mmp(start, start + len, map_permission)
    // 0
}

// YOUR JOB: Implement munmap.
pub fn sys_munmap(start: usize, len: usize) -> isize {
     // Check if start address is page aligned
     if start % PAGE_SIZE != 0 {
        return -1;
    }
    // Align length to page size
    let len_aligned = ((len + PAGE_SIZE - 1) / PAGE_SIZE) * PAGE_SIZE;
    if len_aligned == 0 {
        return -1;
    }

    munmap(start, start + len)
}
/// change data segment size
pub fn sys_sbrk(size: i32) -> isize {
    trace!("kernel: sys_sbrk");
    if let Some(old_brk) = change_program_brk(size) {
        old_brk as isize
    } else {
        -1
    }
}
