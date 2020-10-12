package chatapplication_server.components;

import java.io.*;

public class ByteUtils {
    private static final int DEFAULT_CHUNK_SIZE = 1024;


    /**
     * save bytes to file
     * @param fileName the file to write the supplied bytes
     * @param theBytes the bytes to write to file
     * @throws IOException reports problems saving bytes to file
     */
    public static void saveBytesToFile( String fileName, byte[] theBytes )
            throws IOException {
        saveBytesToStream( new FileOutputStream( fileName ), theBytes );
    }

    /**
     * save bytes to output stream and close the output stream on success and
     * on failure.
     * @param out the output stream to write the supplied bytes
     * @param theBytes the bytes to write out
     * @throws IOException reports problems saving bytes to output stream
     */
    public static void saveBytesToStream( OutputStream out, byte[] theBytes )
            throws IOException {
        try {
            out.write( theBytes );
        }
        finally {
            out.flush();
            out.close();
        }
    }

    /**
     * Loads bytes from the file
     *
     * @param fileName file to read the bytes from
     * @return bytes read from the file
     * @exception IOException reports IO failures
     */
    public static byte[] loadBytesFromFile( String fileName ) throws IOException {
        return loadBytesFromStream( new FileInputStream( fileName ), DEFAULT_CHUNK_SIZE );
    }

    /**
     * Loads bytes from the given input stream until the end of stream
     * is reached.  It reads in at kDEFAULT_CHUNK_SIZE chunks.
     *
     * @return bytes read from the stream
     * @exception IOException reports IO failures
     */
    public static byte[] loadBytesFromStream( InputStream in ) throws IOException {
        return loadBytesFromStream( in, DEFAULT_CHUNK_SIZE );
    }

    /**
     * Loads bytes from the given input stream until the end of stream
     * is reached.  Bytes are read in at the supplied <code>chunkSize</code>
     * rate.
     *
     * @return bytes read from the stream
     * @exception IOException reports IO failures
     */
    public static byte[] loadBytesFromStream( InputStream in, int chunkSize )
            throws IOException {
        if( chunkSize < 1 )
            chunkSize = DEFAULT_CHUNK_SIZE;

        int count;
        ByteArrayOutputStream bo = new ByteArrayOutputStream();
        byte[] b = new byte[chunkSize];
        try {
            while( ( count = in.read( b, 0, chunkSize ) ) > 0 ) {
                bo.write( b, 0, count );
            }
            byte[] thebytes = bo.toByteArray();
            return thebytes;
        }
        finally {
            bo.close();
        }
    }
}
