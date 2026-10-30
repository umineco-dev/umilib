use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;

use super::sync::SpinLock;

/// The unfinished tasks of an executor (weakly), so that dropping the
/// executor can cancel them all, including those waiting on something that
/// will never wake them.
#[derive(Debug)]
pub struct TaskRegistry<T> {
    slots: SpinLock<TaskSlots<T>>,
}

/// The slots of a [`TaskRegistry`]: a task (weakly) per key, and the keys free for reuse.
#[derive(Debug)]
pub struct TaskSlots<T> {
    pub tasks: Vec<Option<Weak<T>>>,
    pub free: Vec<usize>,
}

impl<T> TaskRegistry<T> {
    pub const fn new() -> TaskRegistry<T> {
        TaskRegistry { slots: SpinLock::new(TaskSlots { tasks: Vec::new(), free: Vec::new() }) }
    }

    /// Records `task`; the key to remove it with.
    pub fn insert(&self, task: &Arc<T>) -> usize {
        let mut slots = self.slots.lock();
        let weak = Arc::downgrade(task);
        match slots.free.pop() {
            Some(key) => {
                slots.tasks[key] = Some(weak);
                key
            }
            None => {
                slots.tasks.push(Some(weak));
                slots.tasks.len() - 1
            }
        }
    }

    /// Forgets `task`, recorded under `key` (it finished or is dropped).
    /// Does nothing if the slot of `key` holds another task: a task drained
    /// with [`TaskRegistry::drain`] may be dropped after its key was reused.
    pub fn remove(&self, key: usize, task: &T) {
        let mut slots = self.slots.lock();
        if let Some(slot) = slots.tasks.get_mut(key)
            && slot.as_ref().is_some_and(|weak| core::ptr::eq(weak.as_ptr(), task))
        {
            *slot = None;
            slots.free.push(key);
        }
    }

    /// The tasks recorded and still alive, forgetting them all.
    pub fn drain(&self) -> Vec<Arc<T>> {
        let mut slots = self.slots.lock();
        let tasks = slots.tasks.drain(..).flatten().filter_map(|weak| weak.upgrade()).collect();
        slots.free.clear();
        tasks
    }

    /// The tasks recorded.
    pub fn len(&self) -> usize {
        let slots = self.slots.lock();
        slots.tasks.len() - slots.free.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl<T> Default for TaskRegistry<T> {
    fn default() -> TaskRegistry<T> {
        TaskRegistry::new()
    }
}
