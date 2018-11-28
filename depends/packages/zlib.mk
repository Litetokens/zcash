package=zlib
$(package)_version=1.2.9
$(package)_download_path=https://github.com/madler/zlib/archive/
$(package)_file_name=v$($(package)_version).tar.gz
$(package)_sha256_hash=c1e41e777e007e908ee72ee46a4be1d48b41b55af3440313f36263c08b826c4d

define $(package)_preprocess_cmds
endef

define $(package)_set_vars
$(package)_config_opts=--static
endef

define $(package)_config_cmds
  ./configure --prefix=$(host_prefix) $($(package)_config_opts)
endef

define $(package)_build_cmds
  $(MAKE)
endef

define $(package)_stage_cmds
  $(MAKE) DESTDIR=$($(package)_staging_dir) install
endef

define $(package)_postprocess_cmds
endef