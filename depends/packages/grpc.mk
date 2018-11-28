package=grpc
$(package)_version=1.14.0
$(package)_download_path=https://github.com/grpc/grpc/archive/
$(package)_file_name=v$($(package)_version).tar.gz
$(package)_sha256_hash=ad7686301cf828e2119c66571031bd8d18f93240ae05d81adaa279e1cc91c301

define $(package)_set_vars
  $(package)_config_opts_linux=--with-pic
  $(package)_cxxflags=-std=c++11
endef

define $(package)_preprocess_cmds
  sed -i.old "239s|/usr/local|'$($(package)_staging_dir)/$(host_prefix)'|" Makefile
endef

define $(package)_config_cmds
endef

define $(package)_build_cmds
  $(MAKE)
endef

define $(package)_stage_cmds
  $(MAKE) install
endef

define $(package)_postprocess_cmds
endef