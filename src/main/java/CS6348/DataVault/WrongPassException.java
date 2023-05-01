package CS6348.DataVault;

public class WrongPassException extends Exception
{
	public WrongPassException()
	{
		super("Wrong password provided.");
	}
}