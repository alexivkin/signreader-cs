# Read custom data from a signed file without breaking signatures

Sample code to read custom data that was embedded in a Microsoft Authenticode signed executable or MSI file.

## Building

It can be built on Windows or cross-built for Windows from Linux. The target platform is *Windows*.

* Linux

        docker run --rm -e DOTNET_CLI_TELEMETRY_OPTOUT=true -v $PWD:/app --workdir /app mcr.microsoft.com/dotnet/sdk dotnet publish -c Release -r win-x64

* Windows

Get [dot net sdk](https://download.visualstudio.microsoft.com/download/pr/78a6328f-f563-4a7f-a478-3ed0f2ce8ec6/5beb762f64d8a018a5b9e590bc1531e0/dotnet-sdk-5.0.201-win-x64.exe), then run.

        dotnet publish -c Release -r win-x64

The executable will be stored under `/app/signreader/bin/Release/net5.0/win-x64/publish/`. It is a [self-contained executable](https://docs.microsoft.com/en-us/dotnet/core/deploying/single-file)

## Running

Compile this code. Sign it (optional). Use `signwriter` to store data (strings) in this executable. The run it to extract the data back.

### References

* https://stackoverflow.com/questions/46096886/embed-user-specific-data-into-an-authenticode-signed-installer-on-download
* https://github.com/mgaffigan/passdata
* https://docs.microsoft.com/en-us/visualstudio/install/create-an-offline-installation-of-visual-studio?view=vs-2019
* https://visualstudio.microsoft.com/thank-you-downloading-visual-studio/?sku=professional&rel=16&utm_medium=microsoft&utm_source=docs.microsoft.com&utm_campaign=offline+install&utm_content=download+vs2019
* https://docs.microsoft.com/en-us/windows/msix/package/create-certificate-package-signing
