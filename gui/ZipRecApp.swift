// ZipRecApp.swift — ziprec CLI의 macOS 네이티브 GUI 프론트엔드
// 반디집 프로페셔널 스타일의 5단계 마법사:
//   1 파일 열기 → 2 파일 확인 → 3 복구 설정 → 4 복구 시작 → 5 작업 완료
import SwiftUI
import AppKit
import UniformTypeIdentifiers

// MARK: - ziprec 위치

func locateZiprec() -> String? {
    if let res = Bundle.main.resourceURL?.appendingPathComponent("ziprec").path,
       FileManager.default.isExecutableFile(atPath: res) { return res }
    let beside = Bundle.main.bundleURL
        .deletingLastPathComponent().appendingPathComponent("ziprec").path
    if FileManager.default.isExecutableFile(atPath: beside) { return beside }
    if FileManager.default.isExecutableFile(atPath: "./ziprec") { return "./ziprec" }
    return nil
}

// MARK: - 상태

enum Strategy: String, CaseIterable, Identifiable {
    case dict = "Dictionary + Rules", mask = "Mask", brute = "Brute Force"
    var id: String { rawValue }
}

struct EntryInfo: Identifiable {
    let id = UUID()
    let enc, method, name: String
    let csize, usize: UInt64
}

final class Runner: ObservableObject {
    @Published var running = false
    @Published var progress: Double = 0
    @Published var pctText = ""
    @Published var rateText = "—"
    @Published var etaText = "—"
    @Published var curText = ""
    @Published var paused = false
    @Published var doneTotal = ""
    @Published var descText = ""
    @Published var info: [(String, String)] = []
    @Published var entries: [EntryInfo] = []
    @Published var found: String? = nil
    @Published var verified = false
    @Published var lastEvent = ""
    @Published var logTail: [String] = []
    @Published var gpuLine = ""
    @Published var exitOK = false

    private var proc: Process?
    private var errBuf = "", outBuf = ""

    /// --info 프로브: 탐색 없이 아카이브 정보만 수집 (수 ms)
    func probe(ziprec: String, archive: String, done: @escaping (Bool) -> Void) {
        DispatchQueue.global(qos: .userInitiated).async {
            let p = Process()
            p.executableURL = URL(fileURLWithPath: ziprec)
            p.arguments = [archive, "--info", "-y", "-q"]
            let ep = Pipe()
            p.standardError = ep; p.standardOutput = Pipe()
            do {
                try p.run()
                p.waitUntilExit()
            } catch {
                DispatchQueue.main.async { done(false) }
                return
            }
            let out = String(decoding: ep.fileHandleForReading.readDataToEndOfFile(),
                             as: UTF8.self)
            DispatchQueue.main.async {
                self.info = []; self.entries = []
                for raw in out.components(separatedBy: "\n") {
                    let line = raw.trimmingCharacters(in: .whitespaces)
                    if line.isEmpty { continue }
                    if line.hasPrefix("entry"), let c = line.range(of: " :") {
                        let rest = String(line[c.upperBound...])
                            .trimmingCharacters(in: .whitespaces)
                        let f = rest.components(separatedBy: "  ")
                            .map { $0.trimmingCharacters(in: .whitespaces) }
                            .filter { !$0.isEmpty }
                        if f.count >= 4 {
                            let sz = f[3].components(separatedBy: "->")
                            self.entries.append(EntryInfo(
                                enc: f[0], method: f[1], name: f[2],
                                csize: Self.bytes(sz.first),
                                usize: Self.bytes(sz.count > 1 ? sz[1] : nil)))
                        }
                    } else if let c = line.range(of: " :"),
                              line.distance(from: line.startIndex, to: c.lowerBound) < 14 {
                        let k = String(line[..<c.lowerBound])
                            .trimmingCharacters(in: .whitespaces)
                        let v = String(line[c.upperBound...])
                            .trimmingCharacters(in: .whitespaces)
                        if !self.info.contains(where: { $0.0 == k }) {
                            self.info.append((k, v))
                        }
                    }
                }
                done(p.terminationStatus == 0 && !self.info.isEmpty)
            }
        }
    }

    private static func bytes(_ s: String?) -> UInt64 {
        guard let s = s else { return 0 }
        return UInt64(s.replacingOccurrences(of: "B", with: "")
            .trimmingCharacters(in: .whitespaces)) ?? 0
    }

    func start(ziprec: String, args: [String], keepInfo: Bool) {
        let savedInfo = keepInfo ? info : []
        let savedEntries = keepInfo ? entries : []
        reset()
        info = savedInfo; entries = savedEntries
        let p = Process()
        p.executableURL = URL(fileURLWithPath: ziprec)
        p.arguments = args
        let op = Pipe(), ep = Pipe()
        p.standardOutput = op; p.standardError = ep
        op.fileHandleForReading.readabilityHandler = { [weak self] h in
            let d = h.availableData; if d.isEmpty { return }
            self?.feed(String(decoding: d, as: UTF8.self), stderr: false)
        }
        ep.fileHandleForReading.readabilityHandler = { [weak self] h in
            let d = h.availableData; if d.isEmpty { return }
            self?.feed(String(decoding: d, as: UTF8.self), stderr: true)
        }
        p.terminationHandler = { [weak self] pr in
            DispatchQueue.main.async {
                self?.running = false
                self?.exitOK = (self?.found != nil) || pr.terminationStatus == 0
                if self?.found == nil && self?.lastEvent.isEmpty == true {
                    self?.lastEvent = pr.terminationStatus == 0
                        ? "Done" : "Exited (code \(pr.terminationStatus))"
                }
            }
        }
        do {
            try p.run()
            proc = p
            DispatchQueue.main.async { self.running = true }
        } catch {
            DispatchQueue.main.async { self.lastEvent = "Launch failed: \(error.localizedDescription)" }
        }
    }

    func stop() {
        if let p = proc, p.isRunning { kill(p.processIdentifier, SIGINT) }
    }

    /// SIGSTOP/SIGCONT 일시정지·재개 (메모리 상태 유지, ckpt는 SIGINT가 저장)
    func togglePause() {
        guard let p = proc, p.isRunning else { return }
        kill(p.processIdentifier, paused ? SIGCONT : SIGSTOP)
        paused.toggle()
    }

    private func reset() {
        progress = 0; pctText = ""; rateText = "—"; etaText = "—"
        curText = ""; paused = false
        doneTotal = ""; descText = ""; found = nil; exitOK = false
        verified = false; lastEvent = ""; logTail = []; gpuLine = ""
        errBuf = ""; outBuf = ""
    }

    private func feed(_ s: String, stderr: Bool) {
        var buf = (stderr ? errBuf : outBuf) + s
        var frags: [String] = []
        var start = buf.startIndex
        for i in buf.indices where buf[i] == "\r" || buf[i] == "\n" {
            let frag = String(buf[start..<i])
            if !frag.isEmpty { frags.append(frag) }
            start = buf.index(after: i)
        }
        buf = String(buf[start...])
        if stderr { errBuf = buf } else { outBuf = buf }
        for f in frags { parse(f, stderr: stderr) }
    }

    private func parse(_ raw: String, stderr: Bool) {
        let line = raw.replacingOccurrences(of: "\u{1b}[K", with: "")
            .trimmingCharacters(in: .whitespaces)
        guard !line.isEmpty else { return }
        DispatchQueue.main.async {
            self.logTail.append(line)
            if self.logTail.count > 400 { self.logTail.removeFirst(self.logTail.count - 400) }

            if !stderr {
                if line.hasPrefix("PASSWORD FOUND:") {
                    self.found = String(line.dropFirst(15))
                        .trimmingCharacters(in: .whitespaces)
                    self.progress = 1; self.lastEvent = "Recovery succeeded"
                }
                return
            }
            if line.hasPrefix("["), line.contains("| ETA") {       // 진행률
                if let r1 = line.range(of: "("), let r2 = line.range(of: "%)"),
                   r1.upperBound < r2.lowerBound {
                    self.pctText = String(line[r1.upperBound..<r2.lowerBound]) + "%"
                    self.progress = (Double(self.pctText.dropLast()) ?? 0) / 100
                }
                if let c = line.firstIndex(of: "]") {
                    self.descText = String(line[line.index(after: line.startIndex)..<c])
                    let rest = String(line[line.index(after: c)...])
                    self.doneTotal = rest.components(separatedBy: "(").first?
                        .trimmingCharacters(in: .whitespaces) ?? ""
                }
                let seg = line.components(separatedBy: "|")
                if seg.count >= 2 {
                    self.rateText = seg[0].components(separatedBy: ")").last?
                        .trimmingCharacters(in: .whitespaces) ?? self.rateText
                    self.etaText = seg[1].replacingOccurrences(of: "ETA", with: "")
                        .trimmingCharacters(in: .whitespaces)
                }
                if let cs = seg.last, cs.contains("cur") {
                    self.curText = cs.replacingOccurrences(of: "cur", with: "")
                        .trimmingCharacters(in: .whitespaces)
                }
                return
            }
            if line.hasPrefix("[gpu]") { self.gpuLine = line; return }
            if let c = line.range(of: " :"),
               line.distance(from: line.startIndex, to: c.lowerBound) < 14 {
                let key = String(line[..<c.lowerBound]).trimmingCharacters(in: .whitespaces)
                let val = String(line[c.upperBound...]).trimmingCharacters(in: .whitespaces)
                if key == "verified" { self.verified = true }
                else if !self.info.contains(where: { $0.0 == key }),
                        ["strategy", "space", "threads", "gpu"].contains(key) {
                    self.info.append((key, val))
                }
                return
            }
            if line.hasPrefix("stopped") || line.hasPrefix("exhausted")
                || line.hasPrefix("gpu ") || line.hasPrefix("falling")
                || line.hasPrefix("resuming") || line.hasPrefix("checkpoint")
                || line.hasPrefix("error") {
                self.lastEvent = line
            }
        }
    }
}

// MARK: - 앱

@main
struct ZipRecApp: App {
    var body: some Scene {
        WindowGroup { WizardView() }
            .windowResizability(.contentSize)
    }
}

struct WizardView: View {
    @StateObject private var r = Runner()
    @State private var step = 1
    @State private var archive = ""
    @State private var strategy: Strategy = .dict
    @State private var dictPath = ""
    @State private var mask = "?l?l?l?l?l?l"
    @State private var charset = "?l?d"
    @State private var minLen = 1
    @State private var maxLen = 8
    @State private var threads = ProcessInfo.processInfo.processorCount
    @State private var useGPU = false
    @State private var ownOK = false
    @State private var canResume = false
    @State private var resumeNext = false
    @State private var dropHover = false
    @State private var showLog = false
    @State private var ziprecPath: String? = locateZiprec()
    @State private var probeFailed = false

    private let stepNames = ["Open File", "Verify", "Settings", "Recover", "Done"]

    var body: some View {
        VStack(spacing: 0) {
            // 단계 표시줄
            HStack(spacing: 6) {
                ForEach(1...5, id: \.self) { i in
                    VStack(spacing: 3) {
                        ZStack {
                            Circle()
                                .fill(i == step ? Color.accentColor :
                                      i < step ? Color.accentColor.opacity(0.4)
                                               : Color.gray.opacity(0.25))
                                .frame(width: 30, height: 30)
                            Text("\(i)").font(.callout).bold()
                                .foregroundStyle(i <= step ? .white : .secondary)
                        }
                        Text(LocalizedStringKey(stepNames[i - 1])).font(.caption2)
                            .foregroundStyle(i == step ? .primary : .secondary)
                    }
                    if i < 5 {
                        Rectangle().fill(.gray.opacity(0.3))
                            .frame(height: 1).padding(.bottom, 14)
                    }
                }
            }
            .padding(.horizontal, 20).padding(.top, 16).padding(.bottom, 8)

            Divider()

            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    switch step {
                    case 1: step1
                    case 2: step2
                    case 3: step3
                    case 4: step4
                    default: step5
                    }
                }
                .padding(20)
            }
            .frame(width: 600, height: 420)

            Divider()

            // 하단 버튼
            HStack {
                if step > 1 && step != 4 && step != 5 {
                    Button("< Back") { step -= 1 }
                }
                Spacer()
                bottomButton
            }
            .padding(14)
        }
        .frame(width: 600)
    }

    // MARK: 1단계 — 파일 열기

    var step1: some View {
        VStack(spacing: 16) {
            Text("Drag & drop an encrypted archive into the area below,\nor click 'Open Archive' to choose a file.")
                .multilineTextAlignment(.center)
                .frame(maxWidth: .infinity)
                .padding(.top, 8)

            ZStack {
                Circle()
                    .fill(dropHover ? Color.green.opacity(0.85) : Color.accentColor)
                    .frame(width: 130, height: 130)
                    .shadow(radius: dropHover ? 8 : 3)
                    .scaleEffect(dropHover ? 1.06 : 1)
                Text("Open\nArchive").multilineTextAlignment(.center)
                    .foregroundStyle(.white).bold()
            }
            .frame(maxWidth: .infinity).padding(.vertical, 14)
            .contentShape(Rectangle())
            .onDrop(of: [.fileURL], isTargeted: $dropHover) { providers in
                guard let pr = providers.first else { return false }
                pr.loadItem(forTypeIdentifier: UTType.fileURL.identifier) { item, _ in
                    var url: URL? = item as? URL
                    if url == nil, let d = item as? Data {
                        url = URL(dataRepresentation: d, relativeTo: nil)
                    }
                    if let url {
                        DispatchQueue.main.async { openArchive(url.path) }
                    }
                }
                return true
            }
            .onTapGesture { pickArchive() }

            if !archive.isEmpty {
                LabeledContent("Archive", value: archive)
                    .lineLimit(1).truncationMode(.middle)
            }
            if ziprecPath == nil {
                Label("ziprec binary not found — place it next to this app",
                      systemImage: "exclamationmark.triangle").foregroundStyle(.red)
            }
            Divider()
            Text("Use this tool only on archives you own or are authorized to recover.")
                .font(.caption).foregroundStyle(.secondary)
        }
    }

    // MARK: 2단계 — 파일 확인

    var step2: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Archive opened. Check the information below.")
                .padding(.bottom, 2)
            if probeFailed {
                Label("Could not read the archive, or no encrypted entries were found.",
                      systemImage: "xmark.octagon").foregroundStyle(.red)
            }
            Grid(alignment: .leading, horizontalSpacing: 12, verticalSpacing: 4) {
                ForEach(r.info, id: \.0) { kv in
                    GridRow {
                        Text(kv.0).foregroundStyle(.secondary)
                            .gridColumnAlignment(.trailing)
                        Text(kv.1)
                    }
                }
            }.font(.callout)
            if !r.entries.isEmpty {
                Table(r.entries) {
                    TableColumn("File", value: \.name)
                    TableColumn("Encryption", value: \.enc).width(140)
                    TableColumn("Method", value: \.method).width(70)
                    TableColumn("Size") { e in Text("\(e.usize)B") }.width(70)
                }
                .frame(maxHeight: 150)
            }
            Toggle("I own this file or am authorized to recover it", isOn: $ownOK)
                .padding(.top, 4)
        }
    }

    // MARK: 3단계 — 복구 설정

    var step3: some View {
        VStack(alignment: .leading, spacing: 14) {
            Picker("Recovery mode", selection: $strategy) {
                ForEach(Strategy.allCases) { Text(LocalizedStringKey($0.rawValue)).tag($0) }
            }.pickerStyle(.segmented)

            GroupBox {
                switch strategy {
                case .dict:
                    VStack(alignment: .leading, spacing: 8) {
                        HStack {
                            TextField("Dictionary file (empty = builtin dict + rules)",
                                      text: $dictPath).textFieldStyle(.roundedBorder)
                            Button("Browse…") { pickDict() }
                        }
                        Text("Applies case/number/suffix mutations to a common-password dictionary. The fastest starting point.")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                case .mask:
                    VStack(alignment: .leading, spacing: 8) {
                        HStack {
                            Text("Mask")
                            TextField("?l?l?l?l?l?l", text: $mask)
                                .textFieldStyle(.roundedBorder)
                        }
                        Text("?l lowercase · ?u uppercase · ?d digit · ?s symbol · ?a printable · others literal (e.g. Pass?d?d?d?d)")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                case .brute:
                    VStack(alignment: .leading, spacing: 8) {
                        HStack {
                            Text("Charset")
                            TextField("?l?d", text: $charset)
                                .textFieldStyle(.roundedBorder).frame(width: 150)
                            Spacer()
                            Stepper("Length \(minLen)–\(maxLen)", value: $minLen, in: 1...16)
                                .onChange(of: minLen) { v in if maxLen < v { maxLen = v } }
                            Stepper("", value: $maxLen, in: 1...16).labelsHidden()
                                .onChange(of: maxLen) { v in if minLen > v { minLen = v } }
                        }
                        Text("Tries every combination of the charset within the length range.")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                }
            }

            GroupBox("Performance") {
                HStack {
                    Stepper("CPU threads: \(threads)", value: $threads,
                            in: 1...ProcessInfo.processInfo.processorCount)
                    Spacer()
                    Toggle("GPU acceleration (hashcat)", isOn: $useGPU)
                }
            }

            if canResume {
                GroupBox {
                    Toggle("Resume from previous stop point (checkpoint found)",
                           isOn: $resumeNext)
                }
            }
        }
    }

    // MARK: 4단계 — 복구 시작

    var step4: some View {
        VStack(alignment: .leading, spacing: 14) {
            LabeledContent("Target", value: archive)
                .lineLimit(1).truncationMode(.middle)
            ProgressView(value: r.progress)
                .progressViewStyle(.linear).tint(.accentColor)
            HStack {
                Text(r.pctText.isEmpty ? (r.running ? "Searching…" : "Idle") : r.pctText)
                    .font(.title).monospacedDigit()
                VStack(alignment: .leading) {
                    Text(r.doneTotal).font(.callout).foregroundStyle(.secondary)
                    Text(r.descText).font(.caption).foregroundStyle(.secondary)
                }
                Spacer()
                VStack(alignment: .trailing) {
                    Text(r.rateText).font(.title3).monospacedDigit()
                    Text("Time left \(r.etaText)")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
            if !r.curText.isEmpty {
                HStack {
                    Text("Trying").font(.caption).foregroundStyle(.secondary)
                    Text(r.curText)
                        .font(.system(.callout, design: .monospaced))
                        .foregroundStyle(.orange)
                }
            }
            if r.paused {
                Text("Paused — press Resume to continue")
                    .font(.callout).foregroundStyle(.orange)
            }
            if !r.gpuLine.isEmpty {
                Text(r.gpuLine).font(.caption2).foregroundStyle(.secondary)
                    .lineLimit(2).truncationMode(.middle)
            }
            DisclosureGroup("Log", isExpanded: $showLog) {
                ScrollView {
                    Text(r.logTail.joined(separator: "\n"))
                        .font(.system(.caption2, design: .monospaced))
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .textSelection(.enabled)
                }.frame(height: 130)
            }
            .padding(.top, 6)
        }
    }

    // MARK: 5단계 — 작업 완료

    var step5: some View {
        VStack(spacing: 18) {
            if let pw = r.found {
                Image(systemName: "checkmark.circle.fill")
                    .font(.system(size: 56)).foregroundStyle(.green)
                Text("Password recovered").font(.title2).bold()
                HStack(spacing: 10) {
                    Text(pw).font(.system(.title, design: .monospaced)).bold()
                        .textSelection(.enabled)
                    if r.verified {
                        Text("Verified").font(.caption)
                            .padding(4)
                            .background(.green.opacity(0.15))
                            .clipShape(RoundedRectangle(cornerRadius: 4))
                    }
                }
                HStack {
                    Button("Copy password") {
                        NSPasteboard.general.clearContents()
                        NSPasteboard.general.setString(pw, forType: .string)
                    }
                }
            } else {
                Image(systemName: r.exitOK ? "checkmark.circle" : "xmark.circle")
                    .font(.system(size: 56))
                    .foregroundStyle(r.exitOK ? .orange : .red)
                Text(r.lastEvent.isEmpty ? "Recovery failed" : r.lastEvent)
                    .font(.title3)
                Text("Try a different strategy or a wider search space.")
                    .foregroundStyle(.secondary)
            }
        }
        .frame(maxWidth: .infinity).padding(.top, 20)
    }

    // MARK: 하단 버튼

    @ViewBuilder var bottomButton: some View {
        switch step {
        case 1:
            Button("Next >") { probeThen(2) }
                .disabled(archive.isEmpty || ziprecPath == nil)
                .buttonStyle(.borderedProminent)
        case 2:
            Button("Next >") { step = 3 }
                .disabled(probeFailed || !ownOK)
                .buttonStyle(.borderedProminent)
        case 3:
            Button("Start Recovery") { startCrack() }
                .buttonStyle(.borderedProminent)
        case 4:
            if r.running {
                HStack {
                    Button(r.paused ? "Resume" : "Pause") { r.togglePause() }
                    Button("Stop (save checkpoint)") { r.stop() }.tint(.red)
                }
            } else {
                Button("Next >") { step = 5 }.buttonStyle(.borderedProminent)
            }
        default:
            HStack {
                Button("Try different settings") { step = 3 }
                Button("Start over") {
                    step = 1; archive = ""; canResume = false
                    ownOK = false; resumeNext = false; probeFailed = false
                }
            }
        }
    }

    // MARK: 동작

    func pickArchive() {
        let p = NSOpenPanel()
        p.allowedContentTypes = [.zip]
        p.allowsOtherFileTypes = true
        if p.runModal() == .OK, let u = p.url { openArchive(u.path) }
    }

    func pickDict() {
        let p = NSOpenPanel()
        p.allowsOtherFileTypes = true
        if p.runModal() == .OK, let u = p.url { dictPath = u.path }
    }

    func openArchive(_ path: String) {
        archive = path
        canResume = FileManager.default.fileExists(atPath: path + ".zck")
        probeFailed = false
        probeThen(2)
    }

    func probeThen(_ next: Int) {
        guard let zp = ziprecPath else { return }
        r.probe(ziprec: zp, archive: archive) { ok in
            self.probeFailed = !ok
            self.step = ok ? next : 2
        }
    }

    func startCrack() {
        guard let zp = ziprecPath else { return }
        var args = [archive, "-y", "-t", String(threads)]
        switch strategy {
        case .dict:
            args += dictPath.isEmpty ? ["--rules-builtin"] : ["-d", dictPath]
        case .mask:
            args += ["-m", mask]
        case .brute:
            args += ["-b", "--min", String(minLen), "--max", String(maxLen),
                     "--charset", charset]
        }
        if useGPU { args += ["--gpu"] }
        if resumeNext && canResume { args += ["--resume", archive + ".zck"] }
        r.start(ziprec: zp, args: args, keepInfo: true)
        step = 4
    }
}
