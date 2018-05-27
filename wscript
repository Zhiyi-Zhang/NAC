# -*- Mode: python; py-indent-offset: 4; indent-tabs-mode: nil; coding: utf-8; -*-
VERSION = "0.1.0"
APPNAME = "libndn-nac"
PACKAGE_BUGREPORT = "http://redmine.named-data.net/projects/nac"
GIT_TAG_PREFIX = "nac-"

from waflib import Logs, Utils, Context
import os

def options(opt):
    opt.load(['compiler_c', 'compiler_cxx', 'gnu_dirs'])
    opt.load(['boost', 'default-compiler-flags', 'sanitizers', 'doxygen'],
                 tooldir=['.waf-tools'])

    certopt = opt.add_option_group("NAC Options")
    certopt.add_option('--with-tests', action='store_true', default=False, dest='with_tests',
                           help='''Build unit tests''')

def configure(conf):
    conf.load(['compiler_cxx', 'gnu_dirs', 'boost', 'default-compiler-flags', 'doxygen'])

    if 'PKG_CONFIG_PATH' not in os.environ:
        os.environ['PKG_CONFIG_PATH'] = Utils.subst_vars('${LIBDIR}/pkgconfig', conf.env)
    conf.check_cfg(package='libndn-cxx', args=['--cflags', '--libs'],
                   uselib_store='NDN_CXX', mandatory=True)

    USED_BOOST_LIBS = ['system', 'filesystem', 'iostreams',
                       'program_options',  'thread', 'log', 'log_setup']

    conf.env['WITH_TESTS'] = conf.options.with_tests
    if conf.env['WITH_TESTS']:
        USED_BOOST_LIBS += ['unit_test_framework']
        conf.define('HAVE_TESTS', 1)

    conf.check_boost(lib=USED_BOOST_LIBS, mt=True)
    if conf.env.BOOST_VERSION_NUMBER < 105400:
        Logs.error("Minimum required boost version is 1.54.0")
        Logs.error("Please upgrade your distribution or install custom boost libraries" +
                   " (https://redmine.named-data.net/projects/nfd/wiki/Boost_FAQ)")
        return

    conf.write_config_header('config.hpp')

def build(bld):
    core = bld(
        target="nac",
        features=['cxx', 'cxxshlib'],
        source =  bld.path.ant_glob(['src/**/*.cpp']),
        vnum = VERSION,
        cnum = VERSION,
        use = 'BOOST NDN_CXX',
        includes = ['src', '.'],
        export_includes=['src', '.'],
        install_path='${LIBDIR}'
        )

    # Unit tests
    bld.recurse('tests')

    bld.install_files(
        dest = "%s/nac" % bld.env['INCLUDEDIR'],
        files = bld.path.ant_glob(['src/**/*.hpp', 'src/**/*.h', 'common.hpp']),
        cwd = bld.path.find_dir("src"),
        relative_trick = True,
        )

    bld.install_files(
        dest = "%s/nac" % bld.env['INCLUDEDIR'],
        files = bld.path.get_bld().ant_glob(['src/**/*.hpp', 'common.hpp', 'config.hpp']),
        cwd = bld.path.get_bld().find_dir("src"),
        relative_trick = False,
        )

    bld(features = "subst",
        source='nac.pc.in',
        target='nac.pc',
        install_path = '${LIBDIR}/pkgconfig',
        PREFIX       = bld.env['PREFIX'],
        INCLUDEDIR   = "%s/nac" % bld.env['INCLUDEDIR'],
        VERSION      = VERSION,
        )
