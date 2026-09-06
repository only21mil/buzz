/// Preserve the existing large-stack async runtime initialization for mesh builds.
pub(crate) fn initialize_async_runtime() {
    // mesh-llm's async chains (model download, node start/join) overflow
    // tokio's default 2 MiB worker stacks — a stack-guard SIGABRT, not a
    // panic. Upstream mesh-llm and mesh-console both run on 8 MiB worker
    // stacks for this reason; give Tauri's command runtime the same headroom
    // before anything else touches tauri::async_runtime.
    #[cfg(feature = "mesh-llm")]
    match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_stack_size(crate::mesh_llm::MESH_WORKER_STACK_SIZE)
        .build()
    {
        Ok(runtime) => {
            tauri::async_runtime::set(runtime.handle().clone());
            // Keep the runtime alive for the process lifetime; dropping it
            // would shut down the workers Tauri now depends on.
            std::mem::forget(runtime);
            eprintln!(
                "buzz-mesh: installed tokio runtime with {} MiB worker stacks",
                crate::mesh_llm::MESH_WORKER_STACK_SIZE / (1024 * 1024)
            );
        }
        Err(error) => {
            // Fall back to Tauri's default runtime: the app still works,
            // only deep mesh-llm futures are at risk of stack overflow.
            eprintln!("buzz-mesh: failed to build big-stack tokio runtime, using default: {error}");
        }
    }
}
