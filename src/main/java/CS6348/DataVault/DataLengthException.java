package CS6348.DataVault;

public class DataLengthException extends Exception
{
	public DataLengthException()
	{
		super("Tag data is too long.");
	}
}