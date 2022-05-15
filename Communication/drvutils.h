#pragma once

void DriverInitialization()
{
	DRV().DriverHANDLE();

	if (!DRV().isLoaded())
	{
		cout << xor_a("") << endl;
		//Kernel();
		Mapper();
	}

	DRV().DriverHANDLE();
	if (DRV().isLoaded())
	{
		//cout << xor_a("[+] Driver initialized Successfully...");

		MessageBox(NULL, "[+] Driver initialized Successfully.\n[+] Press 'OK'", "Kernel-Mode", 1);

		//Sleep(2000);

		//system("cls");
	}
	else if (!DRV().isLoaded())
	{
		MessageBox(NULL, "[-] Driver failed to initialize.\n[-] Restart Your PC", "Kernel-Mode", 1);

		//cout << xor_a("[-] Driver failed to initialize") << endl;
	}
}