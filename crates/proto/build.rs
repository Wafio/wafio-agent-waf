// No protoc on the build hosts: protox parses the proto, tonic-prost-build
// generates from the descriptor set.
//
// CertificateInstall holds a private key and prost ignores `debug_redact`, so its derived Debug is
// left out and lib.rs writes one that prints no key. The Debug of ServerMessage goes through it.
const ROOT: &str = "../../proto";
const PROTO: &str = "agent/v1/agent_control.proto";

fn main() {
    println!("cargo:rerun-if-changed={ROOT}/{PROTO}");
    let fds = protox::compile([PROTO], [ROOT]).expect("compile agent_control.proto");
    tonic_prost_build::configure()
        .build_client(true)
        .build_server(true)
        .skip_debug([".wafio.agent.v1.CertificateInstall"])
        .compile_fds(fds)
        .expect("generate AgentControl");
}
