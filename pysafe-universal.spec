# -*- mode: python -*-

block_cipher = None

import platform, os

libext='.so' if platform.system()=='Linux' else '.dll'
dataext='_linux' if platform.system()=='Linux' else '_windows'
p=os.getcwd()

print(f'*\n*Compiling for {platform.system()} from directory {p}\n*')

pat=[p]

# Only install system specific libs for filesize
bins = [(f'{p}/compiled_binaries/*{libext}','/compiled_binaries'),
        (f'{p}/compiled_binaries/*.config','/compiled_binaries')]

datas=[(f'{p}/safenet/extracted_headers/','/safenet/extracted_headers/')]

excludes=['scipy', 'numpy', 'pywin.debugger']

a = Analysis(['pysafe.py'],
             pathex=pat,
             binaries=bins,
             datas=datas,
             hiddenimports=['_cffi_backend'],
             hookspath=[],
             runtime_hooks=[],
             excludes=excludes,
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=block_cipher,
             noarchive=False)

pyz = PYZ(a.pure, a.zipped_data,
             cipher=block_cipher)
exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.zipfiles,
          a.datas,
          [],
          name='pysafe',
          debug=False,
          bootloader_ignore_signals=False,
          strip=False,
          upx=True,
          runtime_tmpdir=None,
          console=True,
          icon = f'{p}/docs/logo.ico')