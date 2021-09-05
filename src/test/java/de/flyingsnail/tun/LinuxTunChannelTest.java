package de.flyingsnail.tun;

import static org.junit.Assert.*;

import java.io.IOException;
import java.nio.ByteBuffer;

import org.bouncycastle.util.encoders.Hex;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

public class LinuxTunChannelTest {
  

  @Before
  public void setUp() throws Exception {
  }

  @After
  public void tearDown() throws Exception {
  }

  @Test
  public void testClose() {
    try {
      LinuxTunChannel testee = new LinuxTunChannel (null);
      testee.close();
      assertFalse(testee.isOpen());
    } catch (IOException e) {
      e.printStackTrace();
      fail(e.getMessage());
    }    
  }

  @Test
  public void testIsOpen() {
    try {
      LinuxTunChannel testee = new LinuxTunChannel (null);
      assertTrue(testee.isOpen());
      testee.close();
      assertFalse(testee.isOpen());
    } catch (IOException e) {
      e.printStackTrace();
      fail(e.getMessage());
    }    
  }

  /**
   * Can we write a direct ByteBuffer?
   */
  @Test
  public void testWriteDirectByteBuffer() {
    ByteBuffer bbDirect = ByteBuffer.allocateDirect(1000);
    bbDirect.put("Hallo".getBytes());
    int length = bbDirect.position();
    bbDirect.flip();
    helperWriteABuffer(bbDirect, length);    
  }

  /**
   * Can we write a Java array-backed ByteBuffer?
   */
  @Test
  public void testWriteArrayBackedByteBuffer() {
    ByteBuffer bbArray = ByteBuffer.allocate(1000);
    bbArray.put("Servus".getBytes());
    int length = bbArray.position();
    bbArray.flip();
    helperWriteABuffer(bbArray, length);    
  }

  /**
   * @param anyTypeOfbb
   * @param length
   */
  private void helperWriteABuffer(ByteBuffer anyTypeOfbb, int length) {
    try {
      LinuxTunChannel testee = new LinuxTunChannel (null);
      int bytesWritten = testee.write (anyTypeOfbb);
      assertEquals(length, bytesWritten);
      assertEquals(length, anyTypeOfbb.position());
      assertEquals(0, anyTypeOfbb.remaining());
      testee.close();
    } catch (IOException e) {
      e.printStackTrace();
      fail(e.getMessage());
    }
  }
  
  /**
   * Can we read to a direct ByteBuffer?
   */
  @Test
  public void testReadDirectByteBuffer() {
    ByteBuffer bbDirect = ByteBuffer.allocateDirect(1000);
    helperReadABuffer(bbDirect);   
  }

  /**
   * Can we write a Java array-backed ByteBuffer?
   * @throws IOException 
   */
  @Test
  public void testReadArrayBackedByteBuffer() throws IOException {
    ByteBuffer bbArray = ByteBuffer.allocate(1000);
    helperReadABuffer(bbArray);
    bbArray.flip();
    System.out.println("Array position ("+bbArray.remaining()+" bytes):");
    Hex.encode(bbArray.array(), bbArray.arrayOffset() + bbArray.position(), bbArray.remaining(), System.out);
    System.out.println();
  }


  private int helperReadABuffer(ByteBuffer anyTypeOfbb) {
    try {
      LinuxTunChannel testee = new LinuxTunChannel (null);
      int bytesRead = testee.read(anyTypeOfbb);      
      assertEquals(bytesRead, anyTypeOfbb.position());
      assertNotEquals(0, bytesRead);
      testee.close();
      return bytesRead;
    } catch (IOException e) {
      e.printStackTrace();
      fail(e.getMessage());
      return 0;
    }
  }

}
