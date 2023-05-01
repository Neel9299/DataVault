package CS6348.DataVault;

public class WrongKeyException extends Exception
{
	public WrongKeyException()
	{
		super("Incorrect key provided.");
	}
}