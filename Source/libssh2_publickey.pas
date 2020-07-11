{ **
  *  Delphi/Pascal Wrapper around the library "libssh2"
  *    Base repository:
  *      https://bitbucket.org/ZeljkoMarjanovic/libssh2-delphi
  *        Contributors:
  *          https://bitbucket.org/jeroenp/libssh2-delphi
  *          https://bitbucket.org/VadimLV/libssh2_delphi
  *          https://github.com/pult/libssh2_delphi/
  * }
unit libssh2_publickey;

// **zm ** translated to pascal

interface

uses
  WinApi.Windows,
  libssh2;

{+// Copyright (c) 2004-2006, Sara Golemon <sarag@libssh2.org> }
{-* All rights reserved. }
{-* }
{-* Redistribution and use in source and binary forms, }
{-* with or without modification, are permitted provided }
{-* that the following conditions are met: }
{-* }
{-* Redistributions of source code must retain the above }
{-* copyright notice, this list of conditions and the }
{-* following disclaimer. }
{-* }
{-* Redistributions in binary form must reproduce the above }
{-* copyright notice, this list of conditions and the following }
{-* disclaimer in the documentation and/or other materials }
{-* provided with the distribution. }
{-* }
{-* Neither the name of the copyright holder nor the names }
{-* of any other contributors may be used to endorse or }
{-* promote products derived from this software without }
{-* specific prior written permission. }
{-* }
{-* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND }
{-* CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, }
{-* INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES }
{-* OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE }
{-* ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR }
{-* CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, }
{-* SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, }
{-* BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR }
{-* SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS }
{-* INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, }
{-* WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING }
{-* NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE }
{-* USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY }
{-* OF SUCH DAMAGE. }
{= }

{+// Note: This include file is only needed for using the }
{-* publickey SUBSYSTEM which is not the same as publickey }
{-* authentication. For authentication you only need libssh2.h }
{-* }
{-* For more information on the publickey subsystem, }
{-* refer to IETF draft: secsh-publickey }
{= }

type
  _LIBSSH2_PUBLICKEY = record end;
  TLIBSSH2_PUBLICKEY = _LIBSSH2_PUBLICKEY;
  PLIBSSH2_PUBLICKEY = ^TLIBSSH2_PUBLICKEY;

  PLIBSSH2_PUBLICKEY_ATTRIBUTE = ^libssh2_publickey_attribute;
  libssh2_publickey_attribute = record
    name: PAnsiChar;
    name_len: ULong;
    value: PAnsiChar;
    value_len: ULong;
    mandatory: AnsiChar;
  end {libssh2_publickey_attribute};

  _libssh2_publickey_list = record
    packet: PByte; {= For freeing }
    name: PUCHAR;
    name_len: LongInt;
    blob: PUCHAR;
    blob_len: ULong;
    num_attrs: ULong;
    attrs: PLIBSSH2_PUBLICKEY_ATTRIBUTE;
{= free me }
  end {_libssh2_publickey_list};
  libssh2_publickey_list = _libssh2_publickey_list;
  Plibssh2_publickey_list = ^libssh2_publickey_list;

{+// Publickey Subsystem*/ }

function libssh2_publickey_init(session: PLIBSSH2_SESSION): PLIBSSH2_PUBLICKEY cdecl;

type
 LIBSSH2_PUBLICKEY_ATTRIBUTE_ARRAY = array of LIBSSH2_PUBLICKEY_ATTRIBUTE;

function libssh2_publickey_add_ex(pkey: PLIBSSH2_PUBLICKEY;
                                  const name: PByte;
                                  name_len: ULong;
                                  const blob: PByte;
                                  blob_len: ULong;
                                  overwrite: AnsiChar;
                                  num_attrs: ULong;
                                  const attrs: LIBSSH2_PUBLICKEY_ATTRIBUTE_ARRAY): Integer; cdecl;

function libssh2_publickey_add(pkey: PLIBSSH2_PUBLICKEY;
                               const name: PByte;
                               const blob: PByte;
                               blob_len: ULong;
                               overwrite: AnsiChar;
                               num_attrs: ULong;
                               const attrs: LIBSSH2_PUBLICKEY_ATTRIBUTE_ARRAY): Integer; inline;

function libssh2_publickey_remove_ex(pkey: PLIBSSH2_PUBLICKEY;
                                     const name: PByte;
                                     name_len: ULong;
                                     const blob: PByte;
                                     blob_len: ULong): Integer; cdecl;

function libssh2_publickey_remove(pkey: PLIBSSH2_PUBLICKEY;
                                     const name: PByte;
                                     const blob: PByte;
                                     blob_len: ULong): Integer; inline;

function libssh2_publickey_list_fetch(pkey: PLIBSSH2_PUBLICKEY;
                                      var num_keys: LongInt;
                                      var pkey_list: PLIBSSH2_PUBLICKEY_LIST): Integer; cdecl;

procedure libssh2_publickey_list_free(pkey: PLIBSSH2_PUBLICKEY;
                                     var pkey_list: LIBSSH2_PUBLICKEY_LIST) cdecl;

function libssh2_publickey_shutdown(pkey: PLIBSSH2_PUBLICKEY): Integer; cdecl;

implementation

function libssh2_publickey_init; external libssh2_name delayed;
function libssh2_publickey_add_ex; external libssh2_name delayed;
function libssh2_publickey_remove_ex; external libssh2_name delayed;
function libssh2_publickey_list_fetch; external libssh2_name delayed;
procedure libssh2_publickey_list_free; external libssh2_name delayed;
function libssh2_publickey_shutdown; external libssh2_name delayed;

function libssh2_publickey_add(pkey: PLIBSSH2_PUBLICKEY; const name: PByte; const blob: PByte;
  blob_len: ULong;  overwrite: AnsiChar; num_attrs: ULong; const attrs: LIBSSH2_PUBLICKEY_ATTRIBUTE_ARRAY): Integer;
begin
  Result := libssh2_publickey_add_ex(pkey, name, Length(PAnsiChar(name)), blob, blob_len, overwrite, num_attrs, attrs);
end;

function libssh2_publickey_remove(pkey: PLIBSSH2_PUBLICKEY; const name: PByte; const blob: PByte; blob_len: ULong): Integer;
begin
  Result := libssh2_publickey_remove_ex(pkey, name, Length(PAnsiChar(name)), blob, blob_len);
end;

end.
