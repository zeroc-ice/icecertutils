@echo off
REM **********************************************************************
REM
REM Copyright (c) 2015-2015 ZeroC, Inc. All rights reserved.
REM
REM **********************************************************************

REM .bat wrapper for iceca python script. Assumes python is in your PATH.

@python "%~dp0iceca"  %*
