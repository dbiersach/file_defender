#!/usr/bin/env bash
# Install the VS Code extensions used by the file_defender workspace.
# This is the primary script for Linux Mint. Run it from a terminal:
#   bash install_vscode_extensions.sh

# C / C++ development with clangd (IntelliSense) and LLDB (debugging)
code --install-extension llvm-vs-code-extensions.vscode-clangd --force
code --install-extension vadimcn.vscode-lldb --force
code --install-extension ms-vscode.cmake-tools --force
code --install-extension twxs.cmake --force

# Python (the offline ML pipeline) with Ruff
code --install-extension ms-python.python --force
code --install-extension ms-python.vscode-pylance --force
code --install-extension charliermarsh.ruff --force

# Quality-of-life helpers
code --install-extension streetsidesoftware.code-spell-checker --force
code --install-extension usernamehw.errorlens --force
code --install-extension eamodio.gitlens --force

# Remove the Microsoft C/C++ IntelliSense engine if present: it conflicts with
# clangd. (cpptools' debugger is replaced here by CodeLLDB.)
code --uninstall-extension ms-vscode.cpptools --force
