package=protobuf
$(package)_version=3.5.0
$(package)_download_path=https://github.com/protocolbuffers/protobuf/archive
$(package)_file_name=v$($(package)_version).tar.gz
$(package)_sha256_hash=0cc6607e2daa675101e9b7398a436f09167dffb8ca0489b0307ff7260498c13c


define $(package)_set_vars
  $(package)_config_opts=--disable-shared
  $(package)_config_opts_linux=--with-pic
  $(package)_cxxflags=-std=c++11
endef

define $(package)_preprocess_cmds
	./autogen.sh
endef

define $(package)_config_cmds
  $($(package)_autoconf)
endef

define $(package)_build_cmds
  $(MAKE)
endef

define $(package)_stage_cmds
  $(MAKE) DESTDIR=$($(package)_staging_dir) install
endef

define $(package)_postprocess_cmds
endef