$scheme = 'http://'
$hostname = '10.10.10.93'
$path = '/transfer.aspx'
$uri = $scheme + $hostname + $path
$proxy = 'http://127.0.0.1:8080'

# Get the page containing the input form and store cookies
$get = Invoke-WebRequest $uri -SessionVariable session
# Filter the required form input to send with the files
$viewState = $get.InputFields | Where-Object {$_.Name -eq '__VIEWSTATE'}
$eventValidation = $get.InputFields | Where-Object {$_.Name -eq '__EVENTVALIDATION'}

# Created a custom test extension list based on: https://hahndorf.eu/blog/iisfileextensions.html 
$fileExtensions = @("asax", "ascx", "asmx", "aspx", "config", "cshtml", "css", "dll", "gif", "htm", "html", "ico", "jpg", "js", "mpg", "png", "txt", "xml", "xsl")
foreach ($ext in $fileExtensions) {
	# Create a dummy file for use with testing
	$newFile = New-Item -ItemType File -Name "test.$ext" -Path $PSScriptRoot -Force
	$headers = @{
		'Content-Type' = 'multipart/form-data'
	}

	# Create a form hash table to send with the request
	$form = @{
		'__VIEWSTATE' = $viewState.Value
		'__EVENTVALIDATION' = $eventValidation.Value
		'btnUpload' = 'Upload'
		'FileUpload1' = $newFile
	}

	# Parameter splatting
	$parameters = @{
		Uri = $uri
		WebSession = $session
		Method = 'Post'
		Headers = $headers
		Form = $form
		#Proxy = $proxy
	}

	try {
		$post = Invoke-WebRequest @parameters -ErrorAction Stop
		if ($post | Select-String 'successfully') {
			Write-Host "File extension: .$ext allowed"
		}
	}
	catch {
		# $_ | Write-Error
	}

	Start-Sleep -Milliseconds 500
	$newFile | Remove-Item -Force
}
