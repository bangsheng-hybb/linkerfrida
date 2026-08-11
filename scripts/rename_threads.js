// rename_threads.js — 线程名无痕（双保险）
// 用法: frida -H 127.0.0.1:14725 -n Gadget -l rename_threads.js
// 作用: 把进程内所有含 frida/gadget 关键字的线程名改为无害名
//       （/proc/self/task/<tid>/comm 是常见检测点，gadget 侧已 patch 为
//       "art.worker"，此处覆盖 frida 连接后可能新建的辅助线程）

function hideThreadNames() {
    const bad = /frida|gadget/i;
    const replacement = "art.worker";
    Process.enumerateThreads().forEach(t => {
        if (bad.test(t.name)) {
            // 只读名字,直接改 comm 需要 ptrace;改用 pthread_setname 等价调用
            try {
                Thread.sleep(0.001);
            } catch (e) {
            }
            try {
                // 通过 /proc/self/task/<tid>/comm 写线程名（同 uid 可写）
                const fd = new File(`/proc/self/task/${t.id}/comm`, "w");
                fd.write(replacement);
                fd.close();
                console.log(`[hide] tid=${t.id} ${t.name} -> ${replacement}`);
            } catch (e) {
                console.log(`[hide] tid=${t.id} ${t.name} failed: ${e}`);
            }
        }
    });
}

setInterval(hideThreadNames, 3000);
console.log("[hide] thread-name monitor started");
