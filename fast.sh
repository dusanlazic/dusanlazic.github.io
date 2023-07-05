#!/bin/bash
if ! type git > /dev/null 2>&1; then
  echo "Git is not installed. Please install Git and rerun this script."
  exit 1
fi

if ! type pip > /dev/null 2>&1; then
  echo "pip is not installed. Please install pip and rerun this script."
  exit 1
fi

echo "Getting Fast..."
if ! git clone --depth 1 -q https://github.com/dusanlazic/fast.git; then
  echo "Failed to clone Fast."
  exit 1
fi

echo "Installing Fast..."
if pip install -q fast/; then
  echo "Fast successfully installed."
  pip show fast | grep Version
else
  echo "Failed to install Fast."
  exit 1
fi

rm -rf fast/
echo "Installation complete. Good luck! 🍀"

exit 0
