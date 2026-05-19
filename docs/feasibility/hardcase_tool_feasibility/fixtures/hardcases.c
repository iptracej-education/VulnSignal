#include <stddef.h>

#define WRAP_GET(o) my_get(o)
#define WRAP_PUT(o) my_put(o)

struct obj {
  int ref;
  int value;
  void (*cb)(struct obj *);
};

struct work_struct {
  void (*func)(struct work_struct *);
};

struct rcu_head {
  void (*func)(struct rcu_head *);
};

void kref_get(int *ref);
void kref_put(int *ref);
void kfree(void *p);
void queue_work(void *wq, struct work_struct *work);
void cancel_work_sync(struct work_struct *work);
void flush_work(struct work_struct *work);
void call_rcu(struct rcu_head *head, void (*func)(struct rcu_head *));

void my_get(struct obj *o) { kref_get(&o->ref); }
void my_put(struct obj *o) { kref_put(&o->ref); }

void cb_a(struct obj *o) { o->value++; }
void cb_b(struct obj *o) { o->value--; }

void invoke_callback(struct obj *o) {
  o->cb(o);
}

void set_callback(struct obj *o, int flag) {
  if (flag) {
    o->cb = cb_a;
  } else {
    o->cb = cb_b;
  }
}

void worker(struct work_struct *work) {
  (void)work;
}

void init_work(struct work_struct *work) {
  work->func = worker;
}

void schedule_lifecycle(struct work_struct *work, struct obj *o) {
  init_work(work);
  WRAP_GET(o);
  queue_work(NULL, work);
  cancel_work_sync(work);
  flush_work(work);
  WRAP_PUT(o);
}

void rcu_free(struct rcu_head *head) {
  kfree(head);
}

void release_rcu(struct rcu_head *head) {
  call_rcu(head, rcu_free);
}

int macro_lifetime(struct obj *o) {
  WRAP_GET(o);
  WRAP_PUT(o);
  return o->value;
}

int main(void) {
  struct obj o;
  set_callback(&o, 1);
  invoke_callback(&o);
  return 0;
}
