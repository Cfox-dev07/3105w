import Foundation
import MachO

enum DylibInjectionError: LocalizedError {
    case appNotFound
    case executableNotFound
    case invalidMachO
    case unsupportedMachO
    case alreadyInjected
    case noLoadCommandSpace
    case copyFailed
    case patchFailed
    case rollbackFailed

    var errorDescription: String? {
        switch self {
        case .appNotFound: return "Không tìm thấy app bundle."
        case .executableNotFound: return "Không tìm thấy executable của app."
        case .invalidMachO: return "Executable không phải Mach-O hợp lệ."
        case .unsupportedMachO: return "Chỉ hỗ trợ Mach-O arm64 64-bit thin trong bản này."
        case .alreadyInjected: return "Dylib đã được load bởi executable."
        case .noLoadCommandSpace: return "Mach-O không còn đủ khoảng trống cho load command mới."
        case .copyFailed: return "Không thể sao chép dylib vào Frameworks."
        case .patchFailed: return "Không thể sửa Mach-O."
        case .rollbackFailed: return "Không thể khôi phục file gốc."
        }
    }
}

struct DylibInjectionReceipt: Codable, Identifiable {
    let id: UUID
    let bundleID: String
    let bundlePath: String
    let executablePath: String
    let dylibPath: String
    let originalExecutableBackup: String
    let installedDylibBackup: String?
    let createdAt: Date
}

enum DylibInjector {
    private static let magic64 = UInt32(0xfeedfacf)
    private static let magic64Swapped = UInt32(0xcffaedfe)
    private static let lcLoadDylib: UInt32 = 0x0c
    private static let align: Int = 8

    static func inject(dylibURL: URL, into bundleID: String) throws -> DylibInjectionReceipt {
        guard let bundlePath = ContainerStore.resolveApplicationBundlePath(bundleID: bundleID) else {
            throw DylibInjectionError.appNotFound
        }

        let bundleURL = URL(fileURLWithPath: bundlePath, isDirectory: true)
        let infoURL = bundleURL.appendingPathComponent("Info.plist")
        guard
            let info = NSDictionary(contentsOf: infoURL),
            let executableName = info["CFBundleExecutable"] as? String,
            !executableName.isEmpty
        else {
            throw DylibInjectionError.executableNotFound
        }

        let executableURL = bundleURL.appendingPathComponent(executableName)
        guard FileManager.default.fileExists(atPath: executableURL.path) else {
            throw DylibInjectionError.executableNotFound
        }

        let fm = FileManager.default
        let frameworks = bundleURL.appendingPathComponent("Frameworks", isDirectory: true)
        try fm.createDirectory(at: frameworks, withIntermediateDirectories: true)

        let dylibName = dylibURL.lastPathComponent
        guard dylibName.hasSuffix(".dylib"), dylibName.count > 6 else {
            throw DylibInjectionError.copyFailed
        }

        let installedDylib = frameworks.appendingPathComponent(dylibName)
        let backupRoot = bundleURL.appendingPathComponent(".3105-backups", isDirectory: true)
        try fm.createDirectory(at: backupRoot, withIntermediateDirectories: true)

        let receiptID = UUID()
        let executableBackup = backupRoot.appendingPathComponent("\(receiptID)-\(executableName).original")
        let dylibBackup: URL? = fm.fileExists(atPath: installedDylib.path)
            ? backupRoot.appendingPathComponent("\(receiptID)-\(dylibName).original")
            : nil

        do {
            try fm.copyItem(at: executableURL, to: executableBackup)
            if let dylibBackup {
                try fm.copyItem(at: installedDylib, to: dylibBackup)
            }

            if fm.fileExists(atPath: installedDylib.path) {
                try fm.removeItem(at: installedDylib)
            }
            try fm.copyItem(at: dylibURL, to: installedDylib)

            var executableData = try Data(contentsOf: executableURL)
            let loadPath = "@executable_path/Frameworks/\(dylibName)"
            try appendLoadDylib(&executableData, path: loadPath)
            try executableData.write(to: executableURL, options: .atomic)

            return DylibInjectionReceipt(
                id: receiptID,
                bundleID: bundleID,
                bundlePath: bundlePath,
                executablePath: executableURL.path,
                dylibPath: installedDylib.path,
                originalExecutableBackup: executableBackup.path,
                installedDylibBackup: dylibBackup?.path,
                createdAt: Date()
            )
        } catch {
            do {
                if fm.fileExists(atPath: executableBackup.path) {
                    if fm.fileExists(atPath: executableURL.path) { try fm.removeItem(at: executableURL) }
                    try fm.copyItem(at: executableBackup, to: executableURL)
                }
                if let dylibBackup {
                    if fm.fileExists(atPath: installedDylib.path) { try fm.removeItem(at: installedDylib) }
                    try fm.copyItem(at: dylibBackup, to: installedDylib)
                } else if fm.fileExists(atPath: installedDylib.path) {
                    try fm.removeItem(at: installedDylib)
                }
            } catch {
                throw DylibInjectionError.rollbackFailed
            }
            if let e = error as? DylibInjectionError { throw e }
            throw DylibInjectionError.patchFailed
        }
    }

    private static func appendLoadDylib(_ data: inout Data, path: String) throws {
        guard data.count >= MemoryLayout<mach_header_64>.size else {
            throw DylibInjectionError.invalidMachO
        }

        let magic = readUInt32(data, 0)
        guard magic == magic64 else {
            if magic == magic64Swapped {
                throw DylibInjectionError.unsupportedMachO
            }
            throw DylibInjectionError.invalidMachO
        }

        let ncmds = Int(readUInt32(data, 16))
        let sizeofcmds = Int(readUInt32(data, 20))
        let commandsStart = 32
        let commandsEnd = commandsStart + sizeofcmds

        guard commandsEnd <= data.count else {
            throw DylibInjectionError.invalidMachO
        }

        var offset = commandsStart
        var minimumPayloadOffset = data.count

        for _ in 0..<ncmds {
            guard offset + 8 <= data.count else { throw DylibInjectionError.invalidMachO }
            let cmd = readUInt32(data, offset)
            let cmdsize = Int(readUInt32(data, offset + 4))
            guard cmdsize >= 8, offset + cmdsize <= data.count else {
                throw DylibInjectionError.invalidMachO
            }

            if cmd == lcLoadDylib, cmdsize >= 24 {
                let nameOffset = Int(readUInt32(data, offset + 8))
                if nameOffset >= 24 && nameOffset < cmdsize {
                    let start = offset + nameOffset
                    let end = min(offset + cmdsize, data.count)
                    if let zero = data[start..<end].firstIndex(of: 0) {
                        let existing = String(data: data[start..<zero], encoding: .utf8) ?? ""
                        if existing == path {
                            throw DylibInjectionError.alreadyInjected
                        }
                    }
                }
            }

            // Find the first file-backed payload after the load-command area.
            if cmd == 0x1 && cmdsize >= 72 { // LC_SEGMENT
                let fileoff = Int(readUInt64(data, offset + 32))
                if fileoff > commandsEnd { minimumPayloadOffset = min(minimumPayloadOffset, fileoff) }
            } else if cmd == 0x19 && cmdsize >= 72 { // LC_SEGMENT_64
                let fileoff = Int(readUInt64(data, offset + 32))
                if fileoff > commandsEnd { minimumPayloadOffset = min(minimumPayloadOffset, fileoff) }
            }

            offset += cmdsize
        }

        let name = Array(path.utf8) + [0]
        let nameOffset = 24
        let rawSize = nameOffset + name.count
        let cmdsize = (rawSize + (align - 1)) & ~(align - 1)
        let newEnd = commandsEnd + cmdsize

        guard newEnd <= minimumPayloadOffset else {
            throw DylibInjectionError.noLoadCommandSpace
        }

        var command = Data(repeating: 0, count: cmdsize)
        writeUInt32(&command, 0, lcLoadDylib)
        writeUInt32(&command, 4, UInt32(cmdsize))
        writeUInt32(&command, 8, UInt32(nameOffset))
        writeUInt32(&command, 12, 2) // timestamp
        writeUInt32(&command, 16, 0x10000) // current version 1.0
        writeUInt32(&command, 20, 0x10000) // compatibility version 1.0
        command.replaceSubrange(nameOffset..<(nameOffset + name.count), with: name)

        data.replaceSubrange(commandsEnd..<newEnd, with: command)

        writeUInt32(&data, 16, UInt32(ncmds + 1))
        writeUInt32(&data, 20, UInt32(sizeofcmds + cmdsize))
    }

    private static func readUInt32(_ data: Data, _ offset: Int) -> UInt32 {
        data.withUnsafeBytes { ptr in
            ptr.loadUnaligned(fromByteOffset: offset, as: UInt32.self)
        }
    }

    private static func readUInt64(_ data: Data, _ offset: Int) -> UInt64 {
        data.withUnsafeBytes { ptr in
            ptr.loadUnaligned(fromByteOffset: offset, as: UInt64.self)
        }
    }

    private static func writeUInt32(_ data: inout Data, _ offset: Int, _ value: UInt32) {
        var v = value.littleEndian
        withUnsafeBytes(of: &v) { bytes in
            data.replaceSubrange(offset..<(offset + 4), with: bytes)
        }
    }
}
