﻿using UnityEngine;
using System.Collections;

public class cur5 : MonoBehaviour
{

    public Texture2D defaultTexture;
    public Texture2D pickupTexture;
    public Texture2D exitTexture;
    public Texture2D examineTexture;
    public CursorMode curMode = CursorMode.Auto;
    public Vector2 hotSpot = Vector2.zero;

    void Start()
    {
        Cursor.SetCursor(defaultTexture, hotSpot, curMode);
    }

    void Update()
    {


    }

    void OnMouseEnter()
    {
        if (gameObject.tag == "exit")
        {
            Cursor.SetCursor(exitTexture, hotSpot, curMode);
        }
        if (gameObject.tag == "pickup")
        {
            Cursor.SetCursor(pickupTexture, hotSpot, curMode);
        }
        if (gameObject.tag == "examine")
        {
            Cursor.SetCursor(examineTexture, hotSpot, curMode);
        }

    }

    void OnMouseExit()

    {
        Cursor.SetCursor(defaultTexture, hotSpot, curMode);
    }
}