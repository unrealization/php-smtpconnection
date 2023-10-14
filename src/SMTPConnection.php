<?php
declare(strict_types=1);
/**
 * @package PHPClassCollection
 * @subpackage SMTPConnection
 * @link http://php-classes.sourceforge.net/ PHP Class Collection
 * @author Dennis Wronka <reptiler@users.sourceforge.net>
 */
namespace unrealization;
/**
 * @package PHPClassCollection
 * @subpackage SMTPConnection
 * @link http://php-classes.sourceforge.net/ PHP Class Collection
 * @author Dennis Wronka <reptiler@users.sourceforge.net>
 * @version 3.0.0
 * @license http://www.gnu.org/licenses/old-licenses/lgpl-2.1.html LGPL 2.1
 */
class SMTPConnection extends TCPConnection
{
	/**
	 * The username used for authentication.
	 * @var string
	 */
	private string $username;
	/**
	 * The password used for authentication.
	 * @var string
	 */
	private string $password;
	/**
	 * The authentication-mechanisms supported by the class.
	 * @var array
	 */
	private array $authMechs = array('CRAM-MD5', 'PLAIN', 'LOGIN');

	/**
	 * Constructor
	 * @param string $host
	 * @param string $username
	 * @param string $password
	 * @param bool $ssl
	 */
	public function __construct(string $host = 'localhost', string $username = '', string $password = '', bool $ssl = false, ?int $port = null)
	{
		if ($ssl === true)
		{
			if (is_null($port))
			{
				parent::__construct($host, 465, $ssl);
			}
			else
			{
				parent::__construct($host, $port, $ssl);
			}
		}
		else
		{
			if (is_null($port))
			{
				parent::__construct($host, 25, $ssl);
			}
			else
			{
				parent::__construct($host, $port, $ssl);
			}
		}

		$this->username = $username;
		$this->password = $password;
	}

	/**
	 * Send the mail.
	 * @param string $mail
	 * @return void
	 * @throws \Exception
	 */
	public function sendMail(string $mail): void
	{
		$matches = array();

		if (isset($_SERVER['SERVER_NAME']))
		{
			$hostname = $_SERVER['SERVER_NAME'];
		}
		elseif (isset($_SERVER['HOSTNAME']))
		{
			$hostname = $_SERVER['HOSTNAME'];
		}
		else
		{
			$hostname = 'localhost.localdomain';
		}

		preg_match('@^From: .*(<.*>)'."\r\n".'@Um', $mail, $matches);

		if (!empty($matches[1]))
		{
			$from = $matches[1];
		}
		else
		{
			throw new \Exception('Cannot find sender address');
		}

		preg_match('@^To: .*(<.*>)'."\r\n".'@Um', $mail, $matches);

		if (!empty($matches[1]))
		{
			$to = $matches[1];
		}
		else
		{
			throw new \Exception('Cannot find recipient address');
		}

		preg_match('@^Cc: .*(<.*>)'."\r\n".'@Um', $mail, $matches);

		if (!empty($matches[1]))
		{
			$cc = $matches[1];
		}
		else
		{
			$cc = '';
		}

		preg_match('@^Bcc: .*(<.*>)'."\r\n".'@Um', $mail, $matches);

		if (!empty($matches[1]))
		{
			$bcc = $matches[1];
		}
		else
		{
			$bcc = '';
		}

		$mail = preg_replace('@^Bcc.*'."\r\n".'@Um', '', $mail);
		$size = strlen($mail);
		$connected = $this->connect();

		if ($connected === false)
		{
			throw new \Exception('Not connected');
		}

		$response = $this->readLine();
		$this->writeLine('EHLO '.$hostname);
		$response = $this->read();

		if (substr($response,0,1) != 2)
		{
			$this->disconnect();
			throw new \Exception('Invalid response from server');
		}

		$authentication = false;
		preg_match('@AUTH (.*)'."\r\n".'@U', $response, $matches);

		if (isset($matches[1]))
		{
			$authMechs=explode(' ', $matches[1]);

			foreach($this->authMechs as $authMech)
			{
				if (in_array($authMech, $authMechs))
				{
					$authentication = $authMech;
					break;
				}
			}
		}

		if (($authentication != false) && (!empty($this->username)) && (!empty($this->password)))
		{
			$this->writeLine('AUTH '.$authentication);
			$response = $this->readLine();

			if (substr($response, 0, 1) != 3)
			{
				$this->disconnect();
				throw new \Exception('Invalid response from server');
			}

			switch($authentication)
			{
				case 'LOGIN':
					$this->writeLine(base64_encode($this->username));
					$response = $this->readLine();

					if (substr($response, 0, 1) != 3)
					{
						$this->disconnect();
						throw new \Exception('Invalid response from server');
					}

					$this->writeLine(base64_encode($this->password));
					break;
				case 'PLAIN':
					$this->writeLine(base64_encode($this->username.chr(0).$this->username.chr(0).$this->password));
					break;
				case 'CRAM-MD5':
					$data = explode(' ', $response);
					$data = base64_decode($data[1]);
					$key = str_pad($this->password, 64, chr(0x00));
					$iPad = str_repeat(chr(0x36), 64);
					$oPad = str_repeat(chr(0x5c), 64);
					$this->writeLine(base64_encode($this->username.' '.md5(($key ^ $oPad).md5(($key ^ $iPad).$data, true))));
					break;
				default:
					$this->disconnect();
					throw new \Exception('Cannot authenticate');
			}

			$response=$this->readLine();

			if (substr($response, 0, 1) != 2)
			{
				$this->disconnect();
				throw new \Exception('Invalid response from server');
			}
		}

		$this->writeLine('MAIL FROM:'.$from.' SIZE='.$size);
		$response = $this->readLine();

		if (substr($response, 0, 1) != 2)
		{
			$this->disconnect();
			throw new \Exception('Invalid response from server');
		}

		$recipientList = explode(',', $to);

		if (!empty($cc))
		{
			$recipientList = array_merge($recipientList, explode(',', $cc));
		}

		if (!empty($bcc))
		{
			$recipientList = array_merge($recipientList, explode(',', $bcc));
		}

		foreach($recipientList as $recipient)
		{
			$matches = array();
			preg_match('@<.*>@', $recipient, $matches);
			
			if (isset($matches[0]))
			{
				$recipient = $matches[0];
			}

			$this->writeLine('RCPT TO:'.$recipient);
			$response = $this->readLine();

			if (substr($response, 0, 1) != 2)
			{
				$this->disconnect();
				throw new \Exception('Invalid response from server');
			}
		}

		$this->writeLine('DATA');
		$response = $this->readLine();

		if (substr($response, 0, 1) != 3)
		{
			$this->disconnect();
			throw new \Exception('Invalid response from server');
		}

		$this->writeLine($mail);
		$this->writeLine('.');
		$response = $this->readLine();

		if (substr($response, 0, 1) != 2)
		{
			$this->disconnect();
			throw new \Exception('Invalid response from server');
		}

		$this->writeLine('QUIT');
		$response = $this->readLine();
		$this->disconnect();
	}
}
?>