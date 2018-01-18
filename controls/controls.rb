control 'Meltdown/Spectre vulnerability KB check' do
  title 'Hot-fix mitigation check for intel chip vulnerability'
  desc 'Checks Windows systems for hotfixes against intel chip vulnerability.'
  impact 1.0

  # KB4056897 KB4056894 # Windows Server 2008 R2
  # KB4056898 KB4056895 # Windows Server 2012 R2
  # KB4056890 # Windows Server 2016

  hotfixes = %w{ KB4056897 KB4056894 KB4056898 KB4056895 KB4056890 }

  describe.one do
    hotfixes.each do |hotfix|
     filter = "HotFixID = '" + hotfix + "'"
       describe wmi({
        class: 'win32_quickfixengineering',
         filter: filter,
       }) do
         its( 'InstalledOn' ) { should_not eq nil }
      end
    end
  end
end
