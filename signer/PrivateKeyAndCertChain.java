/**
* Container class to hold required data in DigitalSigner class.
*
* @author  Alfonso Pauciello
* @version 1.0
* @since   01-01-2018
*/

package signer;

import java.security.PrivateKey;
import java.security.cert.Certificate;

class PrivateKeyAndCertChain
{
	public PrivateKey mPrivateKey;
	public Certificate mCert;
	public Certificate[] mCertificationChain;
	
	public PrivateKeyAndCertChain(PrivateKey mPrivateKey, Certificate mCert, Certificate[] mCertificationChain)
	{
		this.mPrivateKey = mPrivateKey;
		this.mCert = mCert;
		this.mCertificationChain = mCertificationChain;
	}
}