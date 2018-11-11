/**
* Utility class to hold all required info about verification of digital sign on a file.
*
* @author  Alfonso Pauciello
* @version 1.0
* @since   01-01-2018
*/

package signer;

import java.util.ArrayList;

public class VerifySignature extends Thread
{
	private ArrayList<ArrayList<String[]>> subjects;
	private ArrayList<ArrayList<String[]>> issuers;
	private ArrayList<String> plainIssuer;
	private boolean verified;
	
	public static String getFieldName(String field)
	{
		switch (field)
		{
			case "C":
				return "Country";
			case "O":
				return "Organization";
			case "OU":
				return "Org. Unit";
			case "CN":
				return "Common Name";
			case "SERIALNUMBER":
				return "S.Number";
			case "GIVENNAME":
				return "Name";
			case "SURNAME":
				return "Surname";
			case "DN":
				return "Distinguished Name";
			case "T":
				return "Occupation";
		}
		return field;
	}

	/**
	 * This is a Utility class used from DigitalSigner class. This should not be used outside,
	 * because its logic is strictly connected to the above mentioned class.
	 */
	public VerifySignature()
	{
		subjects = new ArrayList<>();
		issuers = new ArrayList<>();
		plainIssuer = new ArrayList<>();
	}
	
	public boolean isVerified()
	{
		return verified;
	}
	
	public void setVerified(boolean verified)
	{
		this.verified = verified;
	}
	
	public ArrayList<ArrayList<String[]>> getSubjects()
	{
		return subjects;
	}
	
	public ArrayList<ArrayList<String[]>> getIssuers()
	{
		return issuers;
	}
	
	public void addSubject(String subject)
	{
		ArrayList<String[]> map = buildArrayMap(subject);
		subjects.add(map);
	}
	
	public void addIssuer(String issuer)
	{
		plainIssuer.add(issuer);
		ArrayList<String[]> map = buildArrayMap(issuer);
		issuers.add(map);
	}
	
	private ArrayList<String[]> buildArrayMap(String data)
	{
		ArrayList<String[]> map = new ArrayList<>();
		String[] params = data.split(",");
		for (int i = 0; i < params.length; ++i)
			map.add(params[i].split("="));
		return map;
	}
}