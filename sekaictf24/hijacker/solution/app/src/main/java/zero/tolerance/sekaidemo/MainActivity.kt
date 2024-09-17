package zero.tolerance.sekaidemo

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.provider.Settings
import android.util.Log
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat

class MainActivity : AppCompatActivity() {
    companion object {
        private val OVERLAY_PERMISSION_REQ_CODE = 100
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContentView(R.layout.activity_main)
        ViewCompat.setOnApplyWindowInsetsListener(findViewById(R.id.main)) { v, insets ->
            val systemBars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
            v.setPadding(systemBars.left, systemBars.top, systemBars.right, systemBars.bottom)
            insets
        }

        if (!isOverlayPermissionGranted()) {
            val intent = Intent(Settings.ACTION_MANAGE_OVERLAY_PERMISSION, Uri.parse("package:$packageName"))
            intent.flags = Intent.FLAG_DEBUG_LOG_RESOLUTION
            startActivityForResult(intent, OVERLAY_PERMISSION_REQ_CODE)
        } else {
            startService(Intent(this, OverlayService::class.java)) //SEKAI{Ev3ry_K3yb0ard_1s_Ins3cur3}
        }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == OVERLAY_PERMISSION_REQ_CODE) {
            if (!Settings.canDrawOverlays(this)) {
                Log.e("tag", "permission not granted")
            } else {
                startService(Intent(this, OverlayService::class.java)) //SEKAI{Ev3ry_K3yb0ard_1s_Ins3cur3}
            }
        }
    }

    /** Checks if the overlay is permitted. */
    private fun isOverlayPermissionGranted() = Settings.canDrawOverlays(this)
}
