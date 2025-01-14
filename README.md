
The Network Simulator, Version 3.30

推奨　環境  
ubuntu 18.04 (Shadowing modelでCGALというライブラリを使用するため)  
ubuntuの最新版ではCGALのインストールができなかった  
================================

## 目次:

1) [NS3環境構築](#環境構築)
2) [ns-3実行](#ns-3実行)
3) [Running ns-3](#running-ns3)

Note:  Much more substantial information about ns-3 can be found at
http://www.nsnam.org

## 環境構築

参考URL
https://qiita.com/dorapon2000/items/5c0c0a399aeee629be63

インストール前の必要なライブラリのインストール
-------------------------------------------------------------------
```
!#/bin/bash

# minimal requirements for Python users (release 3.30 and ns-3-dev)
sudo apt install -y gcc g++ python python3 python3-dev
# minimal requirements for Python (development)
sudo apt install -y python3-setuptools git mercurial
# Netanim animator
sudo apt install -y qt5-default mercurial
# Support for ns-3-pyviz visualizer
sudo apt install -y gir1.2-goocanvas-2.0 python-gi python-gi-cairo python-pygraphviz python3-gi python3-gi-cairo python3-pygraphviz gir1.2-gtk-3.0 ipython ipython3  
# Support for MPI-based distributed emulation
sudo apt install -y openmpi-bin openmpi-common openmpi-doc libopenmpi-dev
# Support for utils/check-style.py code style check program
sudo apt install -y uncrustify
# GNU Scientific Library (GSL) support for more accurate 802.11b WiFi error models (not needed for OFDM):
sudo apt install -y gsl-bin libgsl-dev libgsl23 libgslcblas0
# Database support for statistics framework
sudo apt install -y sqlite sqlite3 libsqlite3-dev
# Xml-based version of the config store (requires libxml2 >= version 2.7)
sudo apt install -y libxml2 libxml2-dev
# Support for generating modified python bindings
sudo apt install -y cmake libc6-dev libc6-dev-i386 libclang-6.0-dev llvm-6.0-dev automake pip
python3 -m pip install --user cxxfilt
# A GTK-based configuration system
sudo apt install -y libgtk2.0-0 libgtk2.0-dev
# To experiment with virtual machines and ns-3
sudo apt install -y vtun lxc
# Support for openflow module (requires some boost libraries)
sudo apt install -y libboost-signals-dev libboost-filesystem-dev

### オンラインでドキュメントを見る場合，ここ以下は不要
# Doxygen and related inline documentation
sudo apt install -y doxygen graphviz imagemagick
sudo apt install -y texlive texlive-extra-utils texlive-latex-extra texlive-font-utils texlive-lang-portuguese dvipng latexmk
# The ns-3 manual and tutorial are written in reStructuredText for Sphinx (doc/tutorial, doc/manual, doc/models), and figures typically in dia (also needs the texlive packages above)
sudo apt install -y python3-sphinx dia
```
---------------------------------------------------------------------------------------------

NS3のインストール  
$ cd  
$ mkdir workspace  
$ cd workspace  
$ git clone https://gitlab.com/nsnam/ns-3-allinone.git  
$ cd ns-3-allinone  

ns-3-allioneディレクトリで私のNS３ファイル群を利用する方はgit cloneでインストールしてください(NS3インストール時に
デフォルトでインストールされるものも含まれます)  
git clone https://github.com/shutoushu/ns3.30.git  

また、私のNS３のファイル群にはCGALライブラリが必要なので、CGALライブラリをインストールします  
sudo apt-get install libcgal-dev  




## ns-3実行

./waf configure  
./waf build  

実行コマンド(例)  
./waf --run "Lsgo-SimulationScenario --buildings=0  --protocol=6 --lossModel=4 --scenario=3 --nodes=300 --seed=10000"  

