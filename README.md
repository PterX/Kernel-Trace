# Kernel-Trace
一个基于uprobe，能同时hook大量用户地址空间函数的kpm内核模块


# 如何使用
在成功加载本项目的kpm模块后，可通过 **dmesg | grep +Test-Log+** 命令查看模块日志，再使用项目user目录下的uprobe_trace_user.h文件提供的用户层接口进行编程即可。trace的输出结果在tracefs文件系统下，可通过 **mount | grep tracefs** 命令查看tracefs所在位置，一般都是在/sys/kernel/tracing，通过 **echo "1" >> /sys/kernel/tracing/tracing_on** 开启日志后通过 **cat /sys/kernel/tracing/trace_pipe | grep +Test-Log+** 查看trace的结果。

**set_module_base**函数用于设置要hook so的基址(打印函数偏移需要用到)。

**set_target_uid**函数用于设置要hook的app的uid(过滤输出需要)。

**set_target_file**函数用于设置要hook so的路径(必须是完整路径)。

**set_fun_info**函数用于在so文件的指定偏移处设置uprobe挂载点，并可传递指定函数名。

**set_fun_info2**函数用于在set_fun_info函数设置成功但失效的情况下，与set_fun_info函数作用一致

**clear_all_uprobes**函数用于清除所有的uprobe挂载点。

上述函数的返回结果有SET_TRACE_SUCCESS、SET_TRACE_ERROR两种，分别表示设置成功和失败。

# 一些疑惑
set_fun_info2函数其实就是将传入的函数偏移-0x1000再传递到内核，为什么要这样做？其实是因为
在内核使用uprobe_register函数注册uprobe挂载点的时候在一些情况下会出现实际注册的函数偏移比
传入的偏移多上0x1000，而如果我们传入的偏移-0x1000就正好抵消了这个影响。至于为什么会这样，
我翻阅linux内核源码发现问题出现于[内存地址计算错误](https://elixir.bootlin.com/linux/v5.15.74/source/kernel/events/uprobes.c#L1004),从这里开始内存地址就多加上了0x1000，我推测是内存页少算了
一页，但是具体原因不清楚。