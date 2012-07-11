require 'cgi'

class TestRunner
  def initialize(project_path, report_assembler)
    @project_path = project_path
    @report_assembler = report_assembler

    @results = {
      :project_name => File.basename(@project_path),
      :timestamp => {:start => nil, :finish => nil}
    }
    [:version, :update, :test].each { |key| @results[key] = default_script_result }
  end
  
  attr_reader :results
  
  def project_name
    @results[:project_name]
  end

  def sort_order
    [sort_file_contents, @results[:project_name]]    
  end

  def check_for_valid_scripts
    check_script('update')
    check_script('version')
    check_script('test')
    check_script('conclusion')
  end
  
  def script_path(name)
    script_path = File.join('.ci', name)
  end
  
  def check_script(name)
    script_path = script_path(name)
    
    Dir.chdir(@project_path) do
      if File.exists?(script_path)
        if !File.stat(script_path).executable?
          msg = "#{@project_path}/.ci/#{name} script not executable"
          Syslog.warning msg
          abort msg
        elsif File.open(script_path).read.empty?
          msg = "#{@project_path}/.ci/#{name} script empty"
          Syslog.warning msg
          abort msg
        end
      else
        msg = "#{@project_path}/.ci/#{name} script missing"
        Syslog.warning msg
        abort msg
      end
    end
  end
  
  def run_script(name, options = {})
    outputs = {
      :output => '',
      :error  => ''
    }
    exit_status  = nil
    exit_message = ''
    start_time = Time.now
    
    Dir.chdir(@project_path) do
      Syslog.debug "Opening up the pipe to #{script_path(name)}"
      
      status = Open4::popen4(script_path(name)) do |pid, stdin, stdout, stderr|
        begin
          stdin.reopen('/dev/null')  # Close to prevent hanging if the script wants input

          select_fds = {
            stdout => :output,
            stderr => :error
          }
          until select_fds.empty?
            ready_fds = select(select_fds.keys, nil, nil, 3600).first

            ready_fds.each do |fd|
              begin
                loop do
                  o = fd.read_nonblock(4096)
                  print o

                  key = select_fds[fd]
                  outputs[key] << escape(o)

                  if options[:stream_test_results?]
                    @results[:test][key] = outputs[key]
                    @report_assembler.update_currently_building(self)
                  end
                end
              rescue Errno::EAGAIN
                # go back to select loop
              rescue EOFError
                select_fds.delete(fd)
              end
            end
          end
        rescue Lockfile::StolenLockError => e
          lockfile_stolen(name, pid)
          raise e
        end
      end
      
      if status.success?
        exit_status  = 0
        exit_message = 'executed successfully'
      elsif status.exited?
        exit_status  = status.exitstatus
        exit_message = "exited with status #{status.exitstatus}"
      elsif status.signaled?
        exit_status  = 128 + status.termsig # mimics shell '$?' behaviour
        exit_message = "died with signal #{status.termsig}"
      else
        exit_status  = 255
        exit_message = 'died of unknown causes'
      end
    end
    
    return {
      :output => outputs[:output].chomp,
      :error  => outputs[:error].chomp,
      :exit_status  => exit_status.to_s,
      :exit_message => exit_message,
      :duration => Time.now - start_time
    }
  end
  
  def conclusion!
    # REFACTOR do this asynchronously so the next tests don't wait on running the conclusion
    
    Dir.chdir(@project_path) do
      Syslog.debug "Passing report to conclusion script at #{script_path('conclusion')}"
      errors = ''
      status = Open4.popen4(script_path('conclusion')) do |pid, stdin, stdout, stderr|
        stdin.puts @results.to_json
        stdin.close
        errors = stderr.read
      end
      
      Syslog.err(errors) if status.exitstatus != '0'
      Syslog.debug "Finished executing conclusion script"
    end
    
  rescue Errno::EPIPE
    Syslog.err "Unknown issue in writing to conclusion script."
  end
  
  def start!
    # REFACTOR to just report whichever scripts are invalid
    check_for_valid_scripts
    
    @results[:timestamp][:start] = Time.now
    Syslog.info "Starting CI for #{project_name}"
  end
    
  def update!
    status :update, "Updating #{project_name}"
    @results[:update] = run_script('update')
  end
  
  def version!
    status :version, "Acquiring build version for #{project_name}"
    @results[:version] = run_script('version')
  end
  
  def test!
    if @results[:version][:exit_status] != '0'
      Syslog.debug "Failed to test #{project_name}; version script #{@results[:version][:exit_message]}"
    elsif @results[:update][:exit_status] != '0'
      Syslog.debug "Failed to test #{project_name}; update script #{@results[:update][:exit_message]}"
    else
      status :test, "Testing #{@results[:project_name]} build #{@results[:version][:output]}"
      @results[:test] = result = run_script('test', :stream_test_results? => true)

      if result[:output] =~ /E{100,}/
        result[:output] = $` + $& + $'.lines.take(50).join + "\n*** #{$&.length} errors detected, output truncated. ***"
      end
    end
    
    @results[:timestamp][:finish] = Time.now
  end
  
  def finished?
    @results[:timestamp][:finish]
  end
  
  def still_building?
    !finished?
  end
  
  private
  
  def sort_file_contents
    sort_file = File.join(@project_path, '.ci', 'sort_order')
    if File.exists?(sort_file)
      File.read(sort_file, 10)
    else
      "\xff" * 10 # comes last
    end
  end
  
  def default_script_result
    {:output => '', :error => '', :exit_status => '', :exit_message => 'not run'}
  end
  
  def escape(text)
    CGI.escapeHTML(text)
  end
  
  def lockfile_stolen(name, pid)
    catch (:success) do
      Syslog.info("Lockfile stolen, interrupting #{name} script (PID #{pid}) ...")
      Process.kill('INT', pid)

      10.times do
        sleep(1)
        throw :success unless process_running?(pid)
      end

      Syslog.info("Forcibly killing #{name} script ...")
      Process.kill('KILL', pid)

      5.times do
        sleep(1)
        throw :success unless process_running?(pid)
      end

      raise "Script refuses to die."
    end
    
    Syslog.info("Successfully terminated #{name} script.")
  rescue Exception => e
    Syslog.err("Error killing #{name} script: #{e.message} (#{e.class})")
  end
  
  def process_running?(pid)
    Process.waitpid(pid, Process::WNOHANG) # reap zombies
    Process.kill(0, pid)
    true
  rescue Errno::ESRCH
    false
  end
  
  def status(stage, message)
    @report_assembler.status(message,
      :project => @results[:project_name],
      :stage   => stage.to_s
    )
    Syslog.debug(message)
  end
end
