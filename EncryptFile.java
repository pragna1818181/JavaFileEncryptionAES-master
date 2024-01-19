import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
 
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import java.awt.event.*;
import java.awt.*;
import java.util.*;


class DemoJFileChooser extends JPanel
   implements ActionListener {
   JButton go;
   JButton go2;
   JButton go3;
   JLabel label;
   JTextField keytext;
   public JFileChooser chooser;
   String choosertitle;
  public String getMyDirectory(){	
  	return chooser.getSelectedFile().toString();
  }
  public String key = "Mary has one cat";
  public DemoJFileChooser() {
    go = new JButton("Choose File");
    go2 = new JButton("Encrypt");
    go3 = new JButton("Decrypt");
    label = new JLabel("");
    keytext = new JTextField("Key: should be of 16 length");
    go.addActionListener(this);
    go2.addActionListener(this);
    go3.addActionListener(this);
    add(go);add(go2);add(go3);add(label);add(keytext);
    go2.setVisible(false);
    go3.setVisible(false);
   }

  public void actionPerformed(ActionEvent e) {
	  if(e.getActionCommand() == "Choose File"){            
	    chooser = new JFileChooser(); 
	    chooser.setCurrentDirectory(new java.io.File("."));
	    chooser.setDialogTitle(choosertitle);
	    chooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
	    //
	    // disable the "All files" option.
	    //
	    chooser.setAcceptAllFileFilterUsed(true);
	    //    
	    if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) { 
	      label.setText(chooser.getSelectedFile().toString()+" file selected");
			go2.setVisible(true);
			go3.setVisible(true);
	      }
	    else {
	      System.out.println("No Selection ");
	      }
	     }
		if(e.getActionCommand() == "Encrypt"){
      key = keytext.getText();
		File inputFile = chooser.getSelectedFile();
		File encryptedFile = new File(inputFile.getName()+".encrypted");
		// File decryptedFile = new File("document.decrypted");
		 
		try {
		    CryptoUtils.encrypt(key, inputFile, encryptedFile);

		    if (inputFile.delete()) { 
		      System.out.println("Deleted the original unencrypted file: " + inputFile.getName());
		    } else {
		      System.out.println("Failed to delete the original file.");
		    }
		    // CryptoUtils.decrypt(key, encryptedFile, decryptedFile);
		} catch (CryptoException ex) {
		    System.out.println(ex.getMessage());
		    ex.printStackTrace();
		}
		}
	  if(e.getActionCommand() == "Decrypt"){
        key = keytext.getText();
        File inputFile = chooser.getSelectedFile();
        // File encryptedFile = new File("document.decrypted");
        File decryptedFile = new File(inputFile.getName().substring(0,inputFile.getName().length()-10));
        //System.out.println(inputFile.getName().substring(0,inputFile.getName().length()-10));
        try {
            // CryptoUtils.encrypt(key, inputFile, encryptedFile);
            CryptoUtils.decrypt(key, inputFile, decryptedFile);

		    if (inputFile.delete()) { 
		      System.out.println("Deleted the original unencrypted file: " + inputFile.getName());
		    } else {
		      System.out.println("Failed to delete the original file.");
		    }
        } catch (CryptoException ex) {
            System.out.println(ex.getMessage());
            ex.printStackTrace();
        }
	  }
	}
  public Dimension getPreferredSize(){
    return new Dimension(500, 500);
    }

  // public static void main(String s[]) {
  //   JFrame frame = new JFrame("");
  //   DemoJFileChooser panel = new DemoJFileChooser();
  //   frame.addWindowListener(
  //     new WindowAdapter() {
  //       public void windowClosing(WindowEvent e) {
  //         System.exit(0);
  //         }
  //       }
  //     );
  //   frame.getContentPane().add(panel,"Center");
  //   frame.setSize(panel.getPreferredSize());
  //   frame.setVisible(true);
  //   }
}
class CryptoUtils {
    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES";
 
    public static void encrypt(String key, File inputFile, File outputFile)
            throws CryptoException {
        doCrypto(Cipher.ENCRYPT_MODE, key, inputFile, outputFile);
    }
 
    public static void decrypt(String key, File inputFile, File outputFile)
            throws CryptoException {
        doCrypto(Cipher.DECRYPT_MODE, key, inputFile, outputFile);
    }
 
    private static void doCrypto(int cipherMode, String key, File inputFile,
            File outputFile) throws CryptoException {
        try {
            Key secretKey = new SecretKeySpec(key.getBytes(), ALGORITHM);
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(cipherMode, secretKey);
             
            FileInputStream inputStream = new FileInputStream(inputFile);
            byte[] inputBytes = new byte[(int) inputFile.length()];
            inputStream.read(inputBytes);
             
            byte[] outputBytes = cipher.doFinal(inputBytes);
             
            FileOutputStream outputStream = new FileOutputStream(outputFile);
            outputStream.write(outputBytes);
             
            inputStream.close();
            outputStream.close();
             
        } catch (NoSuchPaddingException | NoSuchAlgorithmException
                | InvalidKeyException | BadPaddingException
                | IllegalBlockSizeException | IOException ex) {
            throw new CryptoException("Error encrypting/decrypting file", ex);
        }
    }
}
class CryptoException extends Exception {
 
    public CryptoException() {
    }
 
    public CryptoException(String message, Throwable throwable) {
        super(message, throwable);
    }
}
public class EncryptFile{
	public static void main(String[] args) {

		JFrame frame = new JFrame("");
		DemoJFileChooser panel = new DemoJFileChooser();
		frame.addWindowListener(
		  new WindowAdapter() {
		    public void windowClosing(WindowEvent e) {
		      System.exit(0);
		      }
		    }
		  );
		frame.getContentPane().add(panel,"Center");
		frame.setSize(panel.getPreferredSize());
		frame.setVisible(true);
	}
}
