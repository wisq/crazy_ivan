require 'lockfile'

class AlreadyRunningError < StandardError; end

class ProcessManager
  @@lockfile = Lockfile.new('/tmp/crazy_ivan.lock', :retries => 1)
  
  def self.lockfilepath=(filepath)
    @@lockfile = Lockfile.new(filepath, :retries => 1)
  end
  
  def self.acquire_lock!
    Syslog.debug "Acquiring lock"
    @@lockfile.lock do
      Syslog.debug("Locked CI process")
      yield
    end
    Syslog.debug("Unlocked CI process")
  rescue Lockfile::StolenLockError
    msg = "Lockfile has been stolen - aborting"
    Syslog.err msg
    puts msg
    raise AlreadyRunningError, msg
  rescue Lockfile::LockError
    msg = "Detected another running CI process - cannot start"
    Syslog.warning msg
    puts msg
    raise AlreadyRunningError, msg
  end
end