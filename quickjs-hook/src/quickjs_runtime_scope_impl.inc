static void js_runtime_scope_prepend_jobs(const struct list_head *jobs,
                                          struct list_head *destination)
{
    if (jobs->next != jobs) {
        struct list_head *first = jobs->next;
        struct list_head *last = jobs->prev;
        struct list_head *current_first = destination->next;

        destination->next = first;
        first->prev = destination;
        last->next = current_first;
        current_first->prev = last;
    }
}

void JS_Enter(JSRuntime *rt)
{
    JS_UpdateStackTop(rt);
}

void JS_Suspend(JSRuntime *rt, JSRuntimeThreadState *state)
{
    JSRuntimeInternalThreadState *s = (JSRuntimeInternalThreadState *)state;

    s->stack_top = rt->stack_top;
    s->stack_limit = rt->stack_limit;
    s->current_exception = rt->current_exception;
    s->current_exception_is_uncatchable = rt->current_exception_is_uncatchable;
    s->in_out_of_memory = rt->in_out_of_memory;
    s->current_stack_frame = rt->current_stack_frame;
    memcpy(&s->job_list, &rt->job_list, sizeof(rt->job_list));

    rt->stack_top = 0;
    rt->stack_limit = 0;
    rt->current_exception = JS_UNINITIALIZED;
    rt->current_exception_is_uncatchable = FALSE;
    rt->in_out_of_memory = FALSE;
    rt->current_stack_frame = NULL;
    init_list_head(&rt->job_list);
}

void JS_Resume(JSRuntime *rt, const JSRuntimeThreadState *state)
{
    const JSRuntimeInternalThreadState *s =
        (const JSRuntimeInternalThreadState *)state;

    rt->stack_top = s->stack_top;
    rt->stack_limit = s->stack_limit;
    rt->current_exception = s->current_exception;
    rt->current_exception_is_uncatchable = s->current_exception_is_uncatchable;
    rt->in_out_of_memory = s->in_out_of_memory;
    rt->current_stack_frame = s->current_stack_frame;
    js_runtime_scope_prepend_jobs(&s->job_list, &rt->job_list);
}

void JS_Leave(JSRuntime *rt)
{
    rt->stack_top = 0;
    rt->stack_limit = 0;
}
