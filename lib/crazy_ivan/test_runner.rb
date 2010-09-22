require 'cgi'

class TestRunner
  def initialize(project_path, report_assembler)
    @project_path = project_path
    @results = {:project_name => File.basename(@project_path),
                :version => {:output => '', :error => '', :exit_status => ''},
                :update  => {:output => '', :error => '', :exit_status => ''},
                :test    => {:output => '', :error => '', :exit_status => ''},
                :timestamp => {:start => nil, :finish => nil}}
    @report_assembler = report_assembler
  end
  
  attr_reader :results
  
  def project_name
    @results[:project_name]
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
    exit_status = ''
    
    Dir.chdir(@project_path) do
      Syslog.debug "Opening up the pipe to #{script_path(name)}"
      
      status = Open4::popen4(script_path(name)) do |pid, stdin, stdout, stderr|
        begin
          stdin.close  # Close to prevent hanging if the script wants input
        
          select_fds = {
            stdout => :output,
            stderr => :error
          }
          until select_fds.empty?
            ready_fds = select(select_fds.keys, nil, nil, 3600).first
          
            ready_fds.each do |fd|
              if fd.eof?
                select_fds.delete(fd)
                next
              end
              
              o = fd.readpartial(4096)
              print o

              key = select_fds[fd]
              outputs[key] << escape(o)
            
              if options[:stream_test_results?]
                @results[:test][key] = outputs[key]
                @report_assembler.update_currently_building(self)
              end
            end
          end
        rescue Lockfile::StolenLockError => e
          lockfile_stolen(name, pid)
          raise e
        end
      end
      
      exit_status = status.exitstatus
    end
    
    return outputs[:output].chomp, outputs[:error].chomp, exit_status.to_s
  end
  
  def run_conclusion_script
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
    Syslog.debug "Updating #{project_name}"
    @results[:update][:output], @results[:update][:error], @results[:update][:exit_status] = run_script('update')
  end
  
  def version!
    Syslog.debug "Acquiring build version for #{project_name}"
    @results[:version][:output], @results[:version][:error], @results[:version][:exit_status] = run_script('version')
    @results[:version][:output] += '-failed' unless @results[:update][:exit_status] == '0'
  end
  
  def test!
    if @results[:version][:exit_status] == '0'
      Syslog.debug "Testing #{@results[:project_name]} build #{@results[:version][:output]}"
      output, @results[:test][:error], @results[:test][:exit_status] = run_script('test', :stream_test_results? => true)

      if output =~ /E{100,}/
        output = $` + $& + $'.lines.take(50).join + "\n*** #{$&.length} errors detected, output truncated. ***"
      end
      @results[:test][:output] = output
    else
      Syslog.debug "Failed to test #{project_name}; version exit status was #{@results[:version][:exit_status]}"
    end
    
    @results[:timestamp][:finish] = Time.now
    run_conclusion_script
  end
  
  def finished?
    @results[:timestamp][:finish]
  end
  
  def still_building?
    !finished?
  end
  
  private
  
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
end