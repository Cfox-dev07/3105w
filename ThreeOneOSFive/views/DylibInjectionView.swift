import SwiftUI
import UniformTypeIdentifiers

struct DylibInjectionView: View {
    @Environment(\.dismiss) private var dismiss
    @State private var apps: [InstalledApp] = []
    @State private var selectedApp: InstalledApp?
    @State private var selectedDylib: URL?
    @State private var showingImporter = false
    @State private var isWorking = false
    @State private var message: String?
    @State private var showingError = false

    var body: some View {
        NavigationStack {
            Form {
                Section("Target app") {
                    if apps.isEmpty {
                        ProgressView("Đang đọc danh sách app…")
                    } else {
                        Picker("App", selection: Binding(
                            get: { selectedApp?.bundleID ?? "" },
                            set: { id in selectedApp = apps.first(where: { $0.bundleID == id }) }
                        )) {
                            Text("Chọn app").tag("")
                            ForEach(apps) { app in
                                Text("\(app.displayName) — \(app.bundleID)")
                                    .tag(app.bundleID)
                            }
                        }
                    }
                }

                Section("Dylib") {
                    HStack {
                        Text(selectedDylib?.lastPathComponent ?? "Chưa chọn")
                            .lineLimit(1)
                        Spacer()
                        Button("Chọn") { showingImporter = true }
                    }

                    Button {
                        inject()
                    } label: {
                        HStack {
                            Spacer()
                            if isWorking {
                                ProgressView()
                            } else {
                                Label("Inject dylib", systemImage: "bolt.fill")
                            }
                            Spacer()
                        }
                    }
                    .disabled(selectedApp == nil || selectedDylib == nil || isWorking)
                }

                Section("Lưu ý") {
                    Text("Bản thử nghiệm sửa executable của app và thêm LC_LOAD_DYLIB. Việc sửa executable làm chữ ký code của app không còn nguyên vẹn; thiết bị phải có môi trường đã cho phép chạy binary đã sửa.")
                        .font(.footnote)
                    Text("Bản này chỉ xử lý Mach-O arm64 64-bit dạng thin và yêu cầu còn đủ khoảng trống trong load-command area.")
                        .font(.footnote)
                }
            }
            .navigationTitle("Dylib Injector")
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) {
                    Button("Đóng") { dismiss() }
                }
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button {
                        loadApps()
                    } label: {
                        Image(systemName: "arrow.clockwise")
                    }
                }
            }
            .fileImporter(
                isPresented: $showingImporter,
                allowedContentTypes: [
                    UTType(filenameExtension: "dylib") ?? .data
                ],
                allowsMultipleSelection: false
            ) { result in
                switch result {
                case .success(let urls):
                    selectedDylib = urls.first
                case .failure(let error):
                    message = error.localizedDescription
                    showingError = true
                }
            }
            .alert("Dylib Injector", isPresented: $showingError) {
                Button("OK", role: .cancel) {}
            } message: {
                Text(message ?? "")
            }
            .onAppear { loadApps() }
        }
    }

    private func loadApps() {
        isWorking = true
        DispatchQueue.global(qos: .userInitiated).async {
            let metadata = ContainerStore.applicationBundleMetadataCatalog()
            let found = ContainerStore.applyingBundleMetadata(
                to: ContainerStore.installedAppsFromMCM(),
                catalog: metadata
            ).sorted { $0.displayName.localizedCaseInsensitiveCompare($1.displayName) == .orderedAscending }

            DispatchQueue.main.async {
                apps = found
                if selectedApp == nil {
                    selectedApp = found.first
                }
                isWorking = false
            }
        }
    }

    private func inject() {
        guard let app = selectedApp, let dylib = selectedDylib else { return }

        isWorking = true
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                _ = dylib.startAccessingSecurityScopedResource()
                defer { dylib.stopAccessingSecurityScopedResource() }

                let receipt = try DylibInjector.inject(
                    dylibURL: dylib,
                    into: app.bundleID
                )

                DispatchQueue.main.async {
                    message = "Đã inject \(dylib.lastPathComponent) vào \(app.bundleID).\n\n\(receipt.executablePath)"
                    showingError = true
                    isWorking = false
                }
            } catch {
                DispatchQueue.main.async {
                    message = error.localizedDescription
                    showingError = true
                    isWorking = false
                }
            }
        }
    }
}
