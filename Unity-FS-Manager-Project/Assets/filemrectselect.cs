using UnityEngine;
using UnityEngine.UI;
using System.IO;
using System.Runtime.InteropServices;
using UnityEngine.EventSystems;
using System.Collections;

//[RequireComponent(typeof(ScrollRect))]
public class filemrectselect : MonoBehaviour
{
    [SerializeField]
    private float m_lerpTime;
    private ScrollRect m_scrollRect;
    private Button[] m_buttons;
    private int m_index;
    private float m_verticalPosition;
    private bool m_up;
    string simplepath = @"/update/selected.simple";
    private bool m_down;

    public void MoveContentPane(float value)
    {
        var pos = transform.position;
        pos.y += value;
        transform.position = pos;
    }

    public void Start()
    {
        //m_scrollRect = GetComponent<ScrollRect>();
        // m_buttons = GetComponentsInChildren<Button>();
        //  m_buttons[m_index].Select();
        //   m_verticalPosition = 5f- ((float)m_index / (m_buttons.Length - 1));
    }

    public void Update()
    {
         m_up = Input.GetAxisRaw("UP-Dpad") == -1;
         m_down = Input.GetAxisRaw("UP-Dpad") == 1;
       // m_up = Input.GetKeyDown(KeyCode.UpArrow);
      // m_down = Input.GetKeyDown(KeyCode.DownArrow);

        if (!File.Exists(simplepath))
        {

            if (m_up ^ m_down)
            {
                if (m_up)
                {
                    Debug.Log("m-up pressed");
                     MoveContentPane(1.75f);
                    //MoveContentPane(30);
                }

                else if (m_down)
                {
                    Debug.Log("m-down pressed");
                   MoveContentPane(-1.75f);
                }

                //  m_buttons[m_index].Select();
                //  m_verticalPosition = 5f - ((float)m_index / (m_buttons.Length - 1));
            }
        }

        // m_scrollRect.verticalNormalizedPosition = Mathf.Lerp(m_scrollRect.verticalNormalizedPosition, m_verticalPosition, Time.deltaTime / m_lerpTime);
    }
}

/*public class rectselect : MonoBehaviour
{

    RectTransform scrollRectTransform;
    RectTransform contentPanel;
    RectTransform selectedRectTransform;
    GameObject lastSelected;

    void Start()
    {
        scrollRectTransform = GetComponent<RectTransform>();
        contentPanel = GetComponent<ScrollRect>().content;
    }

    void Update()
    {
        // Get the currently selected UI element from the event system.
        GameObject selected = EventSystem.current.currentSelectedGameObject;

        // Return if there are none.
        if (selected == null)
        {
            return;
        }
        // Return if the selected game object is not inside the scroll rect.
        if (selected.transform.parent != contentPanel.transform)
        {
            return;
        }
        // Return if the selected game object is the same as it was last frame,
        // meaning we haven't moved.
        if (selected == lastSelected)
        {
            return;
        }

        // Get the rect tranform for the selected game object.
        selectedRectTransform = selected.GetComponent<RectTransform>();
        // The position of the selected UI element is the absolute anchor position,
        // ie. the local position within the scroll rect + its height if we're
        // scrolling down. If we're scrolling up it's just the absolute anchor position.
        float selectedPositionY = Mathf.Abs(selectedRectTransform.anchoredPosition.y) + selectedRectTransform.rect.height;

        // The upper bound of the scroll view is the anchor position of the content we're scrolling.
        float scrollViewMinY = contentPanel.anchoredPosition.y;
        // The lower bound is the anchor position + the height of the scroll rect.
        float scrollViewMaxY = contentPanel.anchoredPosition.y + scrollRectTransform.rect.height;

        // If the selected position is below the current lower bound of the scroll view we scroll down.
        if (selectedPositionY > scrollViewMaxY)
        {
            float newY = selectedPositionY - scrollRectTransform.rect.height;
            contentPanel.anchoredPosition = new Vector2(contentPanel.anchoredPosition.x, newY);
        }
        // If the selected position is above the current upper bound of the scroll view we scroll up.
        else if (Mathf.Abs(selectedRectTransform.anchoredPosition.y) < scrollViewMinY)
        {
            contentPanel.anchoredPosition = new Vector2(contentPanel.anchoredPosition.x, Mathf.Abs(selectedRectTransform.anchoredPosition.y));
        }

        lastSelected = selected;
    }
}*/
