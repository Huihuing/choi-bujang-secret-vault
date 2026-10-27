# 워치독스 학생 프로젝트 실행: 제공 앱 5189 + 읽기 전용 측정 화면 5191.
# 설치/포장, 관리자 권한 상승, 보안 설정 변경, 자동 실측은 하지 않습니다.
[CmdletBinding()]
param()
Set-StrictMode -Version 3
$ErrorActionPreference='Stop'
$ownedNodes=New-Object Collections.Generic.List[object]
$ownedHelpers=New-Object Collections.Generic.List[object]
$appRoot=Split-Path -Parent $PSScriptRoot
$powerShell=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$currentSid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$nodeDirectory=''
$apps=@(
 [pscustomobject]@{Name='기존 보안 Agent';Port=5189;Server=(Join-Path $appRoot 'src\server.mjs');Launcher=(Join-Path $appRoot 'tools\start-alekov.ps1');Official=$true;Existing=$null},
 [pscustomobject]@{Name='읽기 전용 PC 측정';Port=5191;Server=(Join-Path $PSScriptRoot 'pc-monitor\server.mjs');Launcher=(Join-Path $PSScriptRoot 'pc-monitor\start-watchdogs.ps1');Official=$false;Existing=$null}
)
function Fail([string]$code,[string]$message){
 $failure=New-Object InvalidOperationException($code+': '+$message)
 $failure.Data['WatchdogsKnownFailure']=$true
 throw $failure
}
function New-CleanInfo([string]$file,[string]$arguments){
 $info=New-Object Diagnostics.ProcessStartInfo
 $info.FileName=$file;$info.Arguments=$arguments;$info.WorkingDirectory=$appRoot
 $info.UseShellExecute=$false;$info.CreateNoWindow=$true
 $info.WindowStyle=[Diagnostics.ProcessWindowStyle]::Hidden
 $info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
 $info.StandardOutputEncoding=New-Object Text.UTF8Encoding($false)
 $info.StandardErrorEncoding=New-Object Text.UTF8Encoding($false)
 # 허용한 Windows 실행 경로만 복사합니다. 토큰/AI/DB/NODE_OPTIONS 등은 전달하지 않습니다.
 $info.EnvironmentVariables.Clear()
 foreach($name in @('SystemRoot','WINDIR','SystemDrive','COMSPEC','PATHEXT','TEMP','TMP',
  'USERPROFILE','APPDATA','LOCALAPPDATA','ProgramData','ProgramFiles','ProgramFiles(x86)',
  'ProgramW6432','OS','PROCESSOR_ARCHITECTURE','NUMBER_OF_PROCESSORS')){
  $value=[Environment]::GetEnvironmentVariable($name)
  if($null -ne $value){$info.EnvironmentVariables[$name]=$value}
 }
 $system=Join-Path $env:SystemRoot 'System32'
 $paths=@($system,$env:SystemRoot,(Split-Path -Parent $powerShell))
 if($nodeDirectory){$paths=@($nodeDirectory)+$paths}
 $info.EnvironmentVariables['PATH']=$paths -join ';'
 $info.EnvironmentVariables['PSModulePath']=Join-Path (Split-Path -Parent $powerShell) 'Modules'
 return $info
}
function Read-NodeVersion([string]$path){
 $process=$null
 try{
  $process=[Diagnostics.Process]::Start((New-CleanInfo $path '--version'))
  $output=$process.StandardOutput.ReadToEndAsync()
  $discard=$process.StandardError.ReadToEndAsync()
  if(-not $process.WaitForExit(5000)){return ''}
  if($process.ExitCode -ne 0){return ''}
  return $output.Result.Trim()
 }catch{return ''}
 finally{
  if($null -ne $process){
   if(-not $process.HasExited){$process.Kill();[void]$process.WaitForExit(2000)}
   $process.Dispose()
  }
 }
}
function Read-AppListener($app){
 try{
  $listeners=@(Get-NetTCPConnection -State Listen -ErrorAction Stop | Where-Object {$_.LocalPort -eq $app.Port})
 }catch{Fail 'PORT_CHECK_UNAVAILABLE' '포트 소유자를 일반 권한으로 확인하지 못했습니다. 다른 프로그램은 변경하지 않았습니다.'}
 if($listeners.Count -eq 0){return $null}
 $owners=@($listeners | Select-Object -ExpandProperty OwningProcess -Unique)
 if($owners.Count -ne 1 -or @($listeners | Where-Object {$_.LocalAddress -ne '127.0.0.1'}).Count -gt 0){
  Fail 'PORT_OCCUPIED' ($app.Port.ToString()+' 포트를 다른 서비스가 사용합니다. 종료하거나 포트를 바꾸지 않았습니다.')
 }
 try{
  $cim=Get-CimInstance -ClassName Win32_Process -Filter ('ProcessId = '+[int]$owners[0]) -ErrorAction Stop
  $owner=Invoke-CimMethod -InputObject $cim -MethodName GetOwnerSid -ErrorAction Stop
  $server=[IO.Path]::GetFullPath($app.Server)
  $command=([string]$cim.CommandLine).Replace('/','\')
  $pattern='(?:^|\s)(?:"'+[regex]::Escape($server)+'"|'+[regex]::Escape($server)+')(?=\s|$)'
  if($owner.ReturnValue -ne 0 -or $owner.Sid -ne $currentSid -or
   [IO.Path]::GetFileName([string]$cim.ExecutablePath) -ine 'node.exe' -or $command -notmatch $pattern){
   Fail 'PORT_OWNER_UNVERIFIED' '동일 프로젝트의 현재 사용자 프로세스로 확인되지 않습니다.'
  }
  $process=Get-Process -Id ([int]$owners[0]) -ErrorAction Stop
  [void]$process.Handle
  return [pscustomobject]@{Process=$process;ParentId=[int]$cim.ParentProcessId;Started=$process.StartTime.ToUniversalTime()}
 }catch{Fail 'PORT_OWNER_UNVERIFIED' ($app.Port.ToString()+'의 동일 앱 여부를 확인하지 못했습니다. 기존 프로세스는 유지합니다.')}
}
function Test-AppPage($app){
 $response=$null;$reader=$null
 try{
  $path=if($app.Official){'/api/diagnostics'}else{'/'}
  $request=[Net.HttpWebRequest]::Create('http://127.0.0.1:'+$app.Port+$path)
  $request.Method='GET';$request.Proxy=$null;$request.AllowAutoRedirect=$false
  $request.Timeout=1500;$request.ReadWriteTimeout=1500
  $response=$request.GetResponse()
  if([int]$response.StatusCode -ne 200){return $false}
  $reader=New-Object IO.StreamReader($response.GetResponseStream(),[Text.Encoding]::UTF8)
  $buffer=New-Object char[] 4096;$text=New-Object Text.StringBuilder
  while(($read=$reader.Read($buffer,0,$buffer.Length)) -gt 0){
   if($text.Length+$read -gt 65536){return $false}
   [void]$text.Append($buffer,0,$read)
  }
  if($app.Official){
   $body=$text.ToString() | ConvertFrom-Json
   return ($body.ok -eq $true -and $body.data.component -eq 'on-client')
  }
  return ($text.ToString().Contains('WATCHDOGS') -and
   $text.ToString().Contains('id="refresh-pc"') -and $text.ToString().Contains('id="refresh-network"'))
 }catch{return $false}
 finally{if($null -ne $reader){$reader.Dispose()};if($null -ne $response){$response.Dispose()}}
}
function Start-OwnedApp($app){
 # 사전 확인 뒤 포트가 바뀌었으면 새로 시작하지 않습니다.
 if($null -ne (Read-AppListener $app)){Fail 'PORT_CHANGED' '확인 중 포트 상태가 바뀌었습니다. 다시 실행해 주세요.'}
 $literal=$app.Launcher.Replace("'","''")
 $command="[Console]::OutputEncoding=New-Object Text.UTF8Encoding("+ '$false' + "); & '"+$literal+"'"
 if($app.Official){$command+=' -Background'}
 $encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
 $info=New-CleanInfo $powerShell ('-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand '+$encoded)
 $helper=[Diagnostics.Process]::Start($info)
 [void]$helper.Handle
 $ownedHelpers.Add($helper)
 # 출력은 파일/화면으로 전달하지 않고 계속 비워 파이프 정지를 막습니다.
 $discardOutput=$helper.StandardOutput.ReadToEndAsync()
 $discardError=$helper.StandardError.ReadToEndAsync()
 $started=$helper.StartTime.ToUniversalTime()
 $deadline=[DateTime]::UtcNow.AddSeconds(30)
 $owned=$null
 while([DateTime]::UtcNow -lt $deadline){
  $listener=Read-AppListener $app
  if($null -ne $listener){
   if($listener.ParentId -ne $helper.Id -or $listener.Started -lt $started){
    Fail 'PORT_CHANGED' '시작 중 다른 프로세스가 포트를 사용했습니다. 해당 프로세스는 유지합니다.'
   }
   if($null -eq $owned){$owned=$listener.Process;$ownedNodes.Add($owned)}
   if(Test-AppPage $app){Write-Host ($app.Name+' 시작 확인 · 포트 '+$app.Port);return}
  }
  if($helper.HasExited -and $helper.ExitCode -ne 0){
   Fail 'APP_START_FAILED' ($app.Name+' 실행에 실패했습니다. 기존 앱과 보안 설정은 변경하지 않았습니다.')
  }
  Start-Sleep -Milliseconds 150
 }
 Fail 'APP_START_TIMEOUT' ($app.Name+' 화면 응답을 확인하지 못했습니다. 이번 도구가 시작한 프로세스만 정리합니다.')
}
try{
 foreach($app in $apps){
  foreach($path in @($app.Server,$app.Launcher)){
   if(-not (Test-Path -LiteralPath $path -PathType Leaf)){Fail 'SOURCE_MISSING' '기존 제공 런처와 학생 측정 소스가 필요합니다.'}
  }
 }
 if(-not (Test-Path -LiteralPath $powerShell -PathType Leaf)){Fail 'POWERSHELL_UNAVAILABLE' 'Windows PowerShell 5.1이 필요합니다.'}
 $node=$null
 foreach($candidate in @(Get-Command node -All -CommandType Application -ErrorAction SilentlyContinue)){
  if((Read-NodeVersion $candidate.Source) -eq 'v24.19.0'){$node=$candidate;break}
 }
 if($null -eq $node){Fail 'NODE_24_REQUIRED' '기존 설치에서 Node.js v24.19.0을 찾지 못했습니다. 해당 버전을 준비한 뒤 다시 실행하세요. 자동 설치하지 않습니다.'}
 $nodeDirectory=Split-Path -Parent $node.Source
 # 두 포트를 모두 확인한 다음 시작합니다. 동일 앱이라도 응답을 검증해야 재사용합니다.
 foreach($app in $apps){
  $app.Existing=Read-AppListener $app
  if($null -ne $app.Existing -and -not (Test-AppPage $app)){
   Fail 'APP_RESPONSE_UNVERIFIED' ($app.Port.ToString()+'의 앱 응답을 확인하지 못했습니다. 기존 프로세스는 유지합니다.')
  }
 }
 foreach($app in $apps){
  if($null -ne $app.Existing){Write-Host ($app.Name+' 재사용 · 포트 '+$app.Port)}
  else{Start-OwnedApp $app}
 }
 Write-Host '워치독스 조회 기록·PC 실측: http://127.0.0.1:5191/'
 Write-Host '기존 보안 Agent: http://127.0.0.1:5189/'
 Write-Host '5191 화면에서 핵심 기능을 고르고 다시 조회를 누르세요.'
 Write-Host '실측은 버튼을 누를 때만 수행합니다. SDP 미연결과 Windows 조회 결과는 별개입니다.'
 if($ownedNodes.Count -gt 0){
  Write-Host '이 창을 유지하세요. Ctrl+C로 이번에 시작한 프로세스만 종료하며 재사용한 앱은 유지합니다.'
  while($true){
   foreach($process in $ownedNodes){if($process.HasExited){Fail 'APP_EXITED' '이번에 시작한 앱이 종료됐습니다. 다시 실행해 주세요.'}}
   Start-Sleep -Seconds 1
  }
 }else{Write-Host '두 앱이 이미 실행 중입니다. 기존 실행 창에서 수명을 관리하세요.'}
}catch{
 $known=$_.Exception
 while($null -ne $known -and $known.Data['WatchdogsKnownFailure'] -ne $true){$known=$known.InnerException}
 if($null -ne $known){Write-Host $known.Message -ForegroundColor Yellow}
 else{Write-Host 'WATCHDOGS_LAUNCH_FAILED: 실행 도구에서 확인하지 못한 오류가 발생했습니다. 기존 앱은 유지하고 파일·Node 버전·포트를 확인하세요.' -ForegroundColor Yellow}
 exit 1
}finally{
 # 시작 시 연 프로세스 핸들만 사용합니다. PID 검색/이름 일괄 종료는 하지 않습니다.
 foreach($process in @($ownedNodes.ToArray())+@($ownedHelpers.ToArray())){
  try{if(-not $process.HasExited){$process.Kill();[void]$process.WaitForExit(3000)}}catch{
   Write-Host '이번 실행 프로세스의 종료를 확인하지 못했습니다. 기존 앱을 일괄 종료하지 마세요.' -ForegroundColor Yellow
  }finally{$process.Dispose()}
 }
}
