# Install the VS Code extensions used by the file_defender workspace.
# This is the Windows mirror of install_vscode_extensions.sh. Run it from a
# PowerShell prompt:
#   pwsh -File install_vscode_extensions.ps1
#
# Only the Python half of this project builds on Windows (the fanotify/inotify
# collectors and the daemon are Linux-only), but the editor tooling is the same
# so the two scripts install the same list. Keep both in sync with
# .vscode/extensions.json.

# Silence the Node deprecation warnings the VS Code CLI prints on every call.
$env:NODE_NO_WARNINGS = "1"

# C / C++ development with clangd (IntelliSense) and LLDB (debugging)
code --install-extension llvm-vs-code-extensions.vscode-clangd --force
code --install-extension vadimcn.vscode-lldb --force
code --install-extension ms-vscode.cmake-tools --force
code --install-extension twxs.cmake --force
code --install-extension cschlosser.doxdocgen --force

# Python (the offline ML pipeline) with Ruff
code --install-extension ms-python.python --force
code --install-extension ms-python.vscode-pylance --force
code --install-extension ms-python.debugpy --force
code --install-extension charliermarsh.ruff --force

# Quality-of-life helpers
code --install-extension streetsidesoftware.code-spell-checker --force
code --install-extension usernamehw.errorlens --force
code --install-extension eamodio.gitlens --force
code --install-extension davidanson.vscode-markdownlint --force
code --install-extension mechatroner.rainbow-csv --force
code --install-extension anthropic.claude-code --force

# Remove the Microsoft C/C++ IntelliSense engine if present: it conflicts with
# clangd. (cpptools' debugger is replaced here by CodeLLDB.) This is also listed
# under unwantedRecommendations in .vscode/extensions.json.
code --uninstall-extension ms-vscode.cpptools --force
code --uninstall-extension ms-vscode.cpptools-extension-pack --force
code --uninstall-extension ms-vscode.cpptools-themes --force

# Ruff replaces isort, so remove the standalone extension if it is installed.
code --uninstall-extension ms-python.isort --force
