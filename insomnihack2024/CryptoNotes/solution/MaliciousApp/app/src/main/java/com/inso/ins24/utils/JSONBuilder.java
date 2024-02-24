//Extracted from the target application via JADX
package com.inso.ins24.utils;

import android.os.Parcel;
import android.os.Parcelable;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

public class JSONBuilder implements Parcelable {
    public static final Parcelable.Creator<JSONBuilder> CREATOR = new Parcelable.Creator<JSONBuilder>() {
        @Override // android.os.Parcelable.Creator
        public JSONBuilder[] newArray(int i) {
            return new JSONBuilder[i];
        }
        @Override // android.os.Parcelable.Creator
        public JSONBuilder createFromParcel(Parcel parcel) {
            return new JSONBuilder(parcel);
        }
    };
    private static final Gson JSON = new GsonBuilder().create();
    public Object data;

    public JSONBuilder(Object data) {
        this.data = data;
    }

    private JSONBuilder(Parcel parcel) {
        try {
            this.data = JSON.fromJson(parcel.readString(), (Class<Object>) Class.forName(parcel.readString()));
        } catch (ClassNotFoundException e) {
            throw new RuntimeException(e);
        }
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel parcel, int i) {
        parcel.writeString(this.data.getClass().getCanonicalName());
        parcel.writeString(JSON.toJson(this.data));
    }
}
