// No protoc on the build hosts: protox parses the proto, tonic-prost-build
// generates from the descriptor set.
const ROOT: &str = "../../proto";
const PROTO: &str = "agent/v1/agent_control.proto";

fn main() {
    println!("cargo:rerun-if-changed={ROOT}/{PROTO}");
    let fds = protox::compile([PROTO], [ROOT]).expect("compile agent_control.proto");
    tonic_prost_build::configure()
        .build_client(true)
        .build_server(true)
        .compile_fds(fds)
        .expect("generate AgentControl");
}
