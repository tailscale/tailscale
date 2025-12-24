@echo off
@REM Allows running ./tool/cigocacher on Windows, which doesn't have the x
@REM permission bit and shebang support that we use for Unix.
@REM Requires Git Bash.
bash "%~dp0cigocacher" %*
