{ pkgs ? import <nixpkgs> {} }:

let
  clangStdenv = pkgs.clang.stdenv;
      
  mcl = clangStdenv.mkDerivation {
    pname = "mcl";
    version = "2.14";

    src = pkgs.fetchFromGitHub {
      owner = "herumi";
      repo = "mcl";
      rev = "v2.14";
      sha256 = "sha256-GThR2O9LBWHpt1vMXUpUXYoRKOrWsob3RdZ9KGUznXo=";
    };

    nativeBuildInputs = [ pkgs.gnumake pkgs.gmp pkgs.clang ];

    buildPhase = ''
      make -j 10 \
        CXX=${pkgs.clang}/bin/clang++ \
        CC=${pkgs.clang}/bin/clang
    '';

    installPhase = ''
      mkdir -p $out/include
      mkdir -p $out/lib
      cp -r include/mcl include/cybozu $out/include/
      cp -a lib/* $out/lib/
      '';

    meta = {
      description = "Multiprecision library by herumi (used by pymcl)";
      homepage = "https://github.com/herumi/mcl";
      license = pkgs.lib.licenses.bsd3;
      platforms = pkgs.lib.platforms.unix;
    };
  };

  pymclSrc = pkgs.fetchFromGitHub {
    owner = "bemagri";
    repo = "pymcl";
    rev = "main";
    sha256 = "sha256-l6ROYuJqJ1P6heVtP8IOlOLsqdYPBHKS2aqHVv/2DwI=";
  };

in pkgs.mkShell {
  packages = [
    pkgs.python3
    pkgs.python3Packages.setuptools
    pkgs.python3Packages.pip
    pkgs.pkg-config
    pkgs.cmake
    pkgs.clang
    mcl
  ];

shellHook = ''
  echo "[venv] Setting up Python venv..."
  if [ ! -d .venv ]; then
    python -m venv .venv
  fi
  source .venv/bin/activate

  # Export absolute include/lib paths for setup.py to use
  export MCL_INCLUDE_DIR=${mcl}/include
  export MCL_LIB_DIR=${mcl}/lib

  if ! pip show pymcl > /dev/null 2>&1; then
    echo "[venv] Installing pymcl..."
    rm -rf ./pymcl-install
    mkdir -p ./pymcl-install
    cp -r ${pymclSrc}/* ./pymcl-install
    chmod -R u+w ./pymcl-install

    # Patch setup.py to use absolute include/lib paths
    sed -i '1i import os' ./pymcl-install/setup.py
    
    # Replace "mcl/include" with the evaluated MCL_INCLUDE_DIR
    sed -i "s|\"mcl/include\"|\"$MCL_INCLUDE_DIR\"|g" ./pymcl-install/setup.py

    # Replace all occurrences of "mcl/lib" with the evaluated MCL_LIB_DIR path
    sed -i "s|\"mcl/lib|\"$MCL_LIB_DIR|g" ./pymcl-install/setup.py

    

    export CC=${pkgs.clang}/bin/clang
    export CXX=${pkgs.clang}/bin/clang++
    pip install ./pymcl-install
    echo "[venv] ✅ pymcl installed"
  else
    echo "[venv] ✅ pymcl already installed"
  fi
'';

}
