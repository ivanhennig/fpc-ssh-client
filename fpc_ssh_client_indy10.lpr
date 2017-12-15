program project1;

{$mode objfpc}{$H+}
{$define UseCThreads}
uses {$IFDEF UNIX} {$IFDEF UseCThreads}
  cthreads, {$ENDIF} {$ENDIF}
  Classes,
  SysUtils,
  CustApp,
  libssh2,
  libssh2_sftp,
  IdGlobal,
  IdStack,
  IdStackUnix,
  IdSocketHandle;

type

  { TMyApplication }

  TMyApplication = class(TCustomApplication)
  protected
    procedure DoRun; override;
  public
    constructor Create(TheOwner: TComponent); override;
    destructor Destroy; override;
    procedure WriteHelp; virtual;

    procedure ssh();

  end;

  { TMyApplication }

  procedure TMyApplication.DoRun;
  var
    ErrorMsg: string;
  begin
    // quick check parameters
    ErrorMsg := CheckOptions('h', 'help');
    if ErrorMsg <> '' then
    begin
      ShowException(Exception.Create(ErrorMsg));
      Terminate;
      Exit;
    end;

    // parse parameters
    if HasOption('h', 'help') then
    begin
      WriteHelp;
      Terminate;
      Exit;
    end;

    { add your program here }
    ssh();


    // stop program loop
    Terminate;
  end;

  constructor TMyApplication.Create(TheOwner: TComponent);
  begin
    inherited Create(TheOwner);
    StopOnException := True;
  end;

  destructor TMyApplication.Destroy;
  begin
    inherited Destroy;
  end;

  procedure TMyApplication.WriteHelp;
  begin
    { add your help code here }
    writeln('Usage: ', ExeName, ' -h');
  end;

  procedure TMyApplication.ssh();
  var
    l_session: PLIBSSH2_SESSION;

    l_channel: PLIBSSH2_CHANNEL;

    r: integer;

    l_remote_fingerprint: PAnsiChar;

    l_userauth_list: PAnsiChar;
    l_buffer: PAnsiChar;

    l_host: ansistring;
    l_user: PAnsiChar;
    l_pass: PAnsiChar;
    l_port: integer;

    o_out: integer;

    l_buffer2: array [0..16] of char;

    l_cmd: PAnsiChar;
    i: integer;

    l_socket3: TIdSocketHandle;
  begin
    l_session := nil;
    l_channel := nil;


    l_host := '192.168.0.1';
    l_pass := 'secret';
    l_port := 22;
    l_user := 'ivan';

    try
      try


        GStack := TIdStackUnix.Create;
        l_socket3 := TIdSocketHandle.Create(nil);
        l_socket3.AllocateSocket();
        l_socket3.ReuseSocket := rsOSDependent;
        l_host := GStack.ResolveHost(l_host);
        l_socket3.SetPeer(l_host, l_port);
        l_socket3.Connect;


        l_session := libssh2_session_init();





        if (Assigned(l_session)) then
        begin
          WriteLn('Session created');
        end
        else
        begin
          Exit;
        end;

        libssh2_session_set_blocking(l_session, 0);


        while True do
        begin
          r := libssh2_session_startup(l_session, l_socket3.Handle);
          if (r = 0) then
            Break;
          if (r = LIBSSH2_ERROR_EAGAIN) then
            Continue;
        end;
        if (r > 0) then
        begin
          WriteLn('Handshake failure ');
          Exit;
        end;

        l_remote_fingerprint := libssh2_hostkey_hash(l_session, LIBSSH2_HOSTKEY_HASH_SHA1);

        Write('Fingerprint: ');
        for i := 0 to 19 do
        begin
          Write(Format('%02X', [Ord(l_remote_fingerprint[i])]));
        end;
        WriteLn('');

        while True do
        begin
          l_userauth_list := libssh2_userauth_list(l_session, PAnsiChar(l_user), Length(l_user));
          if (Assigned(l_userauth_list)) then
            Break;

          l_buffer := nil;
          r := libssh2_session_last_error(l_session, l_buffer, o_out, 0);
          if (r = LIBSSH2_ERROR_EAGAIN) then
          begin
            Continue;
          end
          else
          begin
            raise Exception.CreateFmt('Failure: (%d) %s', [r, l_buffer]);
          end;
        end;


        WriteLn(l_userauth_list);

        if Pos('password', l_userauth_list) > 0 then
        begin
          while True do
          begin
            r := libssh2_userauth_password(l_session, l_user, l_pass);
            if (r = 0) then
              Break;

            l_buffer := nil;
            r := libssh2_session_last_error(l_session, l_buffer, o_out, 0);
            if (r = LIBSSH2_ERROR_EAGAIN) then
            begin
              Continue;
            end
            else
            begin
              raise Exception.CreateFmt('Failure: (%d) %s', [r, l_buffer]);
            end;
          end;

        end
        else if Pos('publickey', l_userauth_list) > 0 then
        begin

        end;
        //is authenticated?
        r := libssh2_userauth_authenticated(l_session);
        if (r = 0) then
        begin
          raise Exception.CreateFmt('Failure: (%d) is not authenticated', [r]);
        end;


        while True do
        begin
          l_channel := libssh2_channel_open_ex(l_session, 'session', Length('session'), LIBSSH2_CHANNEL_WINDOW_DEFAULT, LIBSSH2_CHANNEL_PACKET_DEFAULT, nil, 0);
          if (Assigned(l_channel)) then
            Break;
          //waitSock(l_socket, l_session);
          l_buffer := nil;
          r := libssh2_session_last_error(l_session, l_buffer, o_out, 0);
          if (r = LIBSSH2_ERROR_EAGAIN) then
          begin
            Continue;
          end
          else
          begin
            raise Exception.CreateFmt('Failure: (%d) %s', [r, l_buffer]);
          end;
        end;
        if (Assigned(l_channel)) then
        begin
          WriteLn('Channel opened');




          while True do
          begin
            l_cmd := 'echo "ABCAAAAAAAAAAAAAAAAAAAA"';
            l_cmd := 'ls -lash';
            r := libssh2_channel_process_startup(l_channel, 'exec', Length('exec'), l_cmd, Length(l_cmd));
            if (r = 0) then
              Break;
            l_buffer := nil;
            r := libssh2_session_last_error(l_session, l_buffer, o_out, 0);
            if (r = LIBSSH2_ERROR_EAGAIN) then
            begin
              Continue;
            end
            else
            begin
              raise Exception.CreateFmt('Failure: (%d) %s', [r, l_buffer]);
            end;

          end;


          if (True) then
          begin
            WriteLn('Command executed');
            while (True) do
            begin

              for i := 0 to High(l_buffer2) do
              begin
                l_buffer2[i] := #0;
              end;
              r := libssh2_channel_read_ex(l_channel, 0, @l_buffer2, High(l_buffer2));
              if (r > 0) then
              begin
                Write(l_buffer2);
                Continue;
              end;

              if (r = 0) then
                Break;

              l_buffer := nil;
              r := libssh2_session_last_error(l_session, l_buffer, o_out, 0);
              if (r = LIBSSH2_ERROR_EAGAIN) then
              begin
                Continue;
              end
              else
              begin
                raise Exception.CreateFmt('Failure: (%d) %s', [r, l_buffer]);
              end;

            end;

          end;

        end;


      except
        on E: Exception do
        begin
          WriteLn(E.Message);
        end;
      end;
    finally
      if (Assigned(l_channel)) then
      begin
        libssh2_channel_close(l_channel);
        libssh2_channel_free(l_channel);
      end;
      if (Assigned(l_session)) then
      begin
        libssh2_session_disconnect(l_session, 'Tchau');
        libssh2_session_free(l_session);
      end;
      if (Assigned(l_socket3)) then
      begin
        l_socket3.Free;
      end;

      libssh2_exit();
    end;

  end;


var
  Application: TMyApplication;
begin
  Application := TMyApplication.Create(nil);
  Application.Title := 'My Application';
  Application.Run;
  Application.Free;
end.
